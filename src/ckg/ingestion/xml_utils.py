from xml.etree import ElementTree


def local_name(element: ElementTree.Element) -> str:
    return element.tag.rsplit("}", 1)[-1]


def descendants(element: ElementTree.Element, name: str):
    return (candidate for candidate in element.iter() if local_name(candidate) == name)


def first_text(element: ElementTree.Element, name: str) -> str | None:
    for candidate in descendants(element, name):
        text = " ".join(part.strip() for part in candidate.itertext() if part.strip())
        return text or None
    return None
