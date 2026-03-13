from datetime import datetime
from abc import ABC, abstractmethod
from pathlib import Path
import json, os
from typing import Any, Iterable, Sequence

from packageurl import PackageURL
from dataclasses import dataclass

import mobster.sbom.merge as merge 
from mobster.sbom.merge import CDXComponent, SBOMItem, SPDXPackage, CycloneDXMerger

@dataclass
class SBOMElement(SBOMItem):
    data: dict[str,Any]

    def id(self) -> str:
        """No-op since this is a not an actual SBOM."""

    def name(self) -> str:
        """Get the name of the item."""
        self.data["name"]

    def version(self) -> str:
        """No-op since this is a not an actual SBOM."""

    def purl(self) -> PackageURL | None:
        if purl_str := self.data.get("purl"):
            return merge.try_parse_purl(purl_str)
        return None
    
    def unwrap(self) -> dict[str,Any]:
        return self.data 

def wrap_as_element(items: Iterable[dict[str, Any]]) -> list[SBOMElement]:
    """
    Wrap a list of dictionary elements into SBOMElement objects.
    """
    return list(map(SBOMElement, items))

def purl_without_version(purl: PackageURL): 
    '''
    Returns the inputted purl without the version.
    Allows for equality of purls regardless of version
    '''
    purl = purl._replace(version=None)
    return purl

def all_purls(sbom: Sequence[SBOMItem]):
    '''
    returns all the purls for a Sequence of SBOMItem (so, an SBOM)
    '''
    all_purls = {}
    for index, component in enumerate(sbom):
        #strip the version so that version can be ignored in equality check
        all_purls[purl_without_version(component.purl())] = index
    return all_purls

def general_enrich(enrichFunc, target_sbom: Sequence[SBOMItem], incoming_sbom: Sequence[SBOMItem]):
    '''
    generic enrich function for all SBOMItem 
    args: 
    - enrichFunc: the function for enriching target_sbom and incoming_sbom (for example, SPDX-CDX will have a different function that SPDX-SPDX)
    - target_sbom: the SBOM that is being enriched
    - incoming_sbom: the SBOM to extract the enrichment data from
    '''
    target_purls = all_purls(target_sbom)
    
    target_packages = [component.unwrap() for component in target_sbom]
    for element in incoming_sbom: 
        if purl_without_version(element.purl()) in target_purls:
            index = target_purls[purl_without_version(element.purl())]
            component_to_enrich = target_sbom[index]
            newPackage = enrichFunc(component_to_enrich.unwrap(), element.unwrap())
            if newPackage: 
                target_packages[index] = newPackage 
    return target_packages


class SBOMEnricher(ABC):
    
    @abstractmethod 
    def enrich(
        self,
        target_sbom: dict[str, Any],
        incoming_sbom: dict[str, Any],
    ) -> dict[str, Any]:  # pragma: no cover
        """
        Enrich two SBOMs.
        This method should be implemented by subclasses.
        Args:
            target_sbom: The SBOM to enrich
            incoming_sbom: The SBOM to extract fields from and add to the target_sbom
        Returns:
            dict[str, Any]: The enriched SBOM
        """
        raise NotImplementedError("Enrich method logic is implemented in subclasses.")
    

class CycloneDXEnricher(SBOMEnricher):  # pylint: disable=too-few-public-methods
    """
    Enrich class for CycloneDX SBOMs.
    """

    def enrich(self, target_sbom: dict[str, Any], incoming_sbom: dict[str, Any]) -> dict[str, Any]:
        """
        Enrich a CycloneDX SBOM with an SBOM of any type

        Args:
            target_sbom: The SBOM to enrich
            incoming_sbom: The SBOM to extract fields from and add to the target_sbom

        Returns:
            dict[str, Any]: The enriched SBOM
        """
        target_components = merge.wrap_as_cdx(target_sbom["components"])
        try:
            if merge._detect_sbom_type(incoming_sbom) == "cyclonedx":
                incoming_components = merge.wrap_as_cdx(incoming_sbom["components"])
                
                #just merges the tools
                merger = CycloneDXMerger(None)
                merger._merge_tools_metadata(target_sbom, incoming_sbom)
                
                target_sbom["components"] = general_enrich(self.mergeModelCards,target_components, incoming_components)
            else: 
                #TODO: THIS IS NO-OP FOR NOW, NOT SURE WHAT I WOULD EXTRACT FROM SDPX
                incoming_packages = merge.wrap_as_spdx(incoming_sbom["packages"])
                target_sbom["components"] = self.enrich_from_spdx(target_sbom, incoming_packages)
        except ValueError as e: 
            print(f"{e}, treating enrichment file as json")
            incoming_elements = wrap_as_element(incoming_sbom.get("components", []))
            target_sbom["components"] = general_enrich(self.convertToModelCard,target_components, incoming_elements)
        
        return target_sbom
                
    def enrich_from_spdx(self, target_sbom: Sequence[CDXComponent], incoming_sbom: Sequence[SPDXPackage]) -> dict[str, Any]:
        raise NotImplementedError("TODO: implement this")


    def convertToModelCard(self, target_component: dict[str, Any], incoming_component: dict[str,Any]):
        '''
        This is intended for when the incoming component is a json file, not an sbom. 
        We can convert the incoming fields to a model card format, then pass it in the mergeModelCards func
        '''
        incoming_component["modelCard"] = {
            "modelParameters": {},
            "properties": incoming_component.get("data", [])
        }

        return self.mergeModelCards(target_component, incoming_component)
    def mergeModelCards(self, target_component: dict[str,Any], incoming_component: dict[str, Any]):
        '''
        adds all the information from the modelCard of incoming_component to target_component. 
        if target_component doesn't have a modelCard, just adds the whole modelCard of incoming_component 
        '''
        if not "modelCard" in target_component: 
            target_component["modelCard"] = incoming_component["modelCard"]
            return target_component
        
        newModelCard = target_component["modelCard"]

        #TODO: should probably also be adding on to the modelParameters?
        newModelCard["modelParameters"] = incoming_component["modelCard"]["modelParameters"]
        
        if "modelCard" in incoming_component: 
            '''
            parts of a modelCard:
            modelParameters
                - architectureFamily
                - inputs: [{format: value}]
                - modelArchitecture
                - outputs: [{format: value}]
                - task
            properties:
                - {name : value}
            '''
            newProperties = [] if not "properties" in newModelCard else newModelCard["properties"]
            targetProperties = incoming_component["modelCard"]["properties"]
            #add everything from incoming properties that isn't already in the target properties
            [p for p in newProperties if not p in targetProperties]
            newModelCard["properties"] = newProperties + [p for p in newProperties if not p in targetProperties]


        target_component["modelCard"] = newModelCard
        return target_component
        
    
class SPDXEnricher(SBOMEnricher):  # pylint: disable=too-few-public-methods
    """
    Enrich class for SPDX SBOMs.
    """

    def enrich(self, target_sbom: dict[str, Any], incoming_sbom: dict[str, Any]) -> dict[str, Any]:
        """
        Enrich a SPDX SBOM with an SBOM of any type

        Args:
            target_sbom: The SBOM to enrich
            incoming_sbom: The SBOM to extract fields from and add to the target_sbom

        Returns:
            dict[str, Any]: The enriched SBOM
        """
        target_packages = merge.wrap_as_spdx(target_sbom.get("packages", []))
        try:
            if merge._detect_sbom_type(incoming_sbom) == "cyclonedx":
                target_sbom["creationInfo"] = self.addToTools(target_sbom["creationInfo"], incoming_sbom["metadata"]["tools"], float(incoming_sbom["specVersion"]))
                target_sbom["packages"] = general_enrich(self.enrichPackage, target_packages, merge.wrap_as_cdx(incoming_sbom.get("components", [])))
            else: 
                target_sbom["creationInfo"]["creators"].extend(incoming_sbom["creation_info"]["creators"])
                target_sbom["packages"] = general_enrich(self.enrichPackageAnnotations, target_packages, merge.wrap_as_spdx(incoming_sbom.get("components", [])))
        except ValueError as e:
            print(f"{e}, treating enrichment file as json")
            target_sbom["packages"] = general_enrich(self.addAsAnnotations, target_packages, wrap_as_element(incoming_sbom.get("components", [])))

        
        return target_sbom
        
    def addToTools(self, creationInfo: dict[str,Any], tools, version: float):
        '''
        adds all tooling information from the the incoming CDX sbom to the target SPDX sbom
        args: 
        - creationInfo: the creation info for the target SPDX sbom
        - tools: CDX tools component (from the incoming sbom)
        - version: CDX version of the incoming CDX sbom
        '''
        #>=1.5 has different tooling format than <1.5, accounts for the different versions
        if version >= 1.5:
            for component in tools["components"]:
                creationInfo["creators"].append(f"Tool: {component["name"]}")
            return creationInfo
        
        for tool in tools:
            creationInfo["creators"].append(f"Tool: {tool["name"]}")
            if "vendor" in tool:
                creationInfo["creators"].append(f"Organization: {tool["vendor"]}")
            #no SPDX equivalent for Person (it was removed in <1.5, so ignoring it)

    
    def enrichPackageAnnotations(self, package1: dict[str,Any], package2: dict[str,Any]):
        '''
        add all annotations from package2 to package1. 
        Intended use case: SPDX-SPDX, so both package1 and package2 are expected to be in SPDX 2.3 
        '''
        package1["annotations"].extend(package2["annotations"])
        return package1
        
    def enrichPackage(self, package: dict[str,Any], component: dict[str,Any]):
        '''
        adds all data from a CDX component modelCard to an SPDX package. For now, this only looks in the modelCard field
        This function uses a chart that has equivalents for every AI CDX field to SPDX 3.0 field. 
        However, Hermeto and Syft only produce up to version 2.3, which doesn't support AI fields. 
        So, this first converts the keyword to SPDX 3.0, then adds the field as an annotation. 
        When support for SPDX 3.0 exists, this should instead add to the AI fields section of the document
        '''
        
        if "modelCard" in component:
            modelCard = component["modelCard"]
            annotations = []
            
            for field in modelCard['properties']:
                fieldName, fieldValue = field['name'], field['value']

                #bomFormat doesn't go in SPDX and serialNumber gets rebuilt as the SPDX id
                #specversion doesn't matter because we're using the SPDX version of the original
                prefer_original = ['bomFormat', 'serialNumber', 'specVersion', 'external_references', 'downloadLocation', 'version']
                if fieldName in prefer_original:
                    continue

                script_path = Path(__file__).resolve()
                script_dir = script_path.parent
                
                spdxFieldName = self.getFieldName(f"{script_dir}/enrich_tools/SPDXmappings2.3.json", fieldName)
                #don't overwrite the field if its in the original SBOM, but add it in if its not
                if spdxFieldName and not (fieldName in package):
                    package[spdxFieldName] = fieldValue 
                    continue 

                
                spdxAIFieldName = self.getFieldName(f"{script_dir}/enrich_tools/SPDXmappingAI.json", fieldName)
                if spdxAIFieldName:   
                    self.makeAnnotationFromField(spdxAIFieldName, fieldValue) 
                    annotations.append(self.makeAnnotationFromField(spdxAIFieldName, fieldValue))
                    continue 

                print(f"The field {fieldName} does not correspond to any SPDX field or AI field. Skipping over field {field}")

            package["annotations"].extend(annotations)

        return package
        
    #TODO i may have made the annotations too constrictive... either have this check my spdx fields file or make the other function not check them
    def addAsAnnotations(self, target_component: dict[str,Any], incoming_component: dict[str,Any]):
        '''
        creates annotations from incoming_component. The intended use case of this is SPDX-JSON
        
        raises: 
            KeyError: The incoming JSON is expected to have a certain format. If it doesn't this throws an error 
        '''
        try:
            newAnnotations = [self.makeAnnotationFromField(element["name"], element["value"]) for element in incoming_component["data"]]
            target_component["annotations"].extend(newAnnotations)
            return target_component
        except KeyError as e:
            print("ERROR: input file expected to be of a particular format, however encountered a KeyError, so something is wrong. Please fix the input file and try again")
            raise e
    def makeAnnotationFromField(self, field, value):
        '''
        creates an SPDX 2.3 style annotation from a field and a value
        '''
        annotation = {"annotationDate": datetime.now().strftime("%Y-%m-%dT%H:%M:%SZ"),
                      "annotationType" : "OTHER",
                      "annotator": "Tool: OWASP AIBOM Generator",
                      "comment" : f"{field} : {value}"}
        return annotation 
    
    def getFieldName(self, file_path, fieldName):
        '''
        gets the SPDX equivalent of a CDX field name from a json file located at file_path
        '''
        try:
            with open(file_path, 'r') as f:
                mappings = json.load(f)
        except Exception as e:
            print(f"An unexpected error occurred: {e}")
            raise e
        if fieldName in mappings:
            return  mappings[fieldName]['SPDX_Equivalent']
        return None




def _create_enricher(
    target_sbom: dict[str, Any]
) -> SBOMEnricher:
    """
    Creates a merger for the given SBOMs.
    """
    target_type = merge._detect_sbom_type(target_sbom)

    if target_type == "cyclonedx":
        return CycloneDXEnricher()

    return SPDXEnricher() 

async def enrich_sbom(
    target_sbom: Path, incoming_sbom: Path | None = None
) -> dict[str, Any]:
    """
    Merge multiple SBOMs.

    This is the main entrypoint function for enriching two SBOMs.
    Currently supports:
        - SPDX-SPDX
        - SPDX-CDX
        - SPDX-JSON
        - CDX-CDX
        - CDX-JSON
    **CDX-SPDX is still WIP

    Args:
        target_sbom: the base SBOM file to be enriched. This can be of format SPDX & CDX
        incoming_sbom: the SBOM to extract the enrichment data from. This can be of format SPDX, CDX, or a JSON

    Returns:
        The enriched SBOM

    Raises:
        ValueError: If the target_sbom and incoming_sbom are not present
    """

    if not target_sbom or not incoming_sbom:
        raise ValueError("A target SBOM path and an incoming SBOM is required to enrich an SBOM.")
    
    target_sbom_loaded = await merge.load_sbom_from_json(target_sbom)
    incoming_sbom_loaded = await merge.load_sbom_from_json(incoming_sbom)
    #we only need the type of the target SBOM to create the enricher
    enricher = _create_enricher(target_sbom_loaded)
    return enricher.enrich(target_sbom_loaded, incoming_sbom_loaded)