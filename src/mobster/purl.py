from packageurl import PackageURL


class PURL:
    """
    A package URL wrapper implementing comparison methods.
    """

    def __init__(self, value: str | PackageURL) -> None:
        if isinstance(value, str):
            self.raw_purl = PackageURL.from_string(value)
        else:
            self.raw_purl = value

    @property
    def normalized(self) -> PackageURL:
        """
        Return the value of the normalized PURL.

        Returns:
            PackageURL: A PackageURL object with only the "normalized" fields:
                name, type, version, namespace
        """
        return PackageURL(
            name=self.raw_purl.name,
            type=self.raw_purl.type,
            version=self.raw_purl.version,
            namespace=self.raw_purl.namespace,
        )

    @property
    def raw(self) -> PackageURL:
        """
        Return the value of the PackageURL as passed to the object constructor.
        """
        return self.raw_purl

    # TODO: implement comparisons also with str and PackageURL?
    def __eq__(self, other: object, /) -> bool:
        """
        Compare two PURLs using only the normalized fields.
        """
        if not isinstance(other, PURL):
            return False

        return self.normalized.to_string() == other.normalized.to_string()

    def __hash__(self) -> int:
        """
        Return a hash of the PURL using only the normalized fields.
        """
        return hash(self.normalized.to_string())
