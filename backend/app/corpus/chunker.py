"""Section to citation-bearing chunk.  OWNER: Prerana

Each chunk carries its own citation_label, so retrieval hands the model the
citation directly instead of asking it to infer which section it is reading.
Inference is exactly where hallucinated citations come from.

Splitting policy, in one line: cut only at a sub-clause boundary, never inside a
sentence. A chunk that begins halfway through a proviso retrieves badly and
quotes worse, and a half-sentence quote is exactly what the faithfulness
guardrail rejects at verification time.
"""

import re
from dataclasses import dataclass

from app.corpus.dpdp_act import ACT_SECTIONS
from app.corpus.dpdp_rules import RULES

SOURCE_ACT = "dpdp_act"
SOURCE_RULES = "dpdp_rules"


@dataclass
class StatutoryChunk:
    source: str
    section_id: str
    section_title: str
    citation_label: str
    chunk_index: int
    text: str


# An enumerator such as "(2) ", "(a) " or "(iii) ". Matching one is not enough to
# justify a cut: "sub-sections (1) and (3)" contains two of them mid-sentence.
_ENUMERATOR = re.compile(r"\((?:\d{1,2}|[a-z]{1,4}|[ivxlcIVXLC]{1,5})\)\s")

# A cut is legitimate only where the preceding text has actually been closed off.
# This is what stops a cross-reference being mistaken for a new clause.
_CLOSERS = frozenset(".;:-" + chr(0x2014) + chr(0x2013))  # em dash, en dash

# Free-standing blocks that read as units, so they should begin a chunk if they
# begin anything at all.
_BLOCKS = ("Illustration.", "Illustrations.", "Explanation.", "Note:")

# Fallback boundary: end of sentence, before a capital, a quote or an enumerator.
_SENTENCE = re.compile(r"(?<=[.;])\s+(?=[A-Z(“])")


def _cut_points(text: str) -> list[int]:
    """Offsets where a new sub-clause or block demonstrably begins."""
    cuts: set[int] = set()

    def closed_before(index: int) -> bool:
        head = text[:index].rstrip()
        return bool(head) and head[-1] in _CLOSERS

    for match in _ENUMERATOR.finditer(text):
        if match.start() and closed_before(match.start()):
            cuts.add(match.start())

    for block in _BLOCKS:
        start = 0
        while (found := text.find(block, start)) != -1:
            if found and closed_before(found):
                cuts.add(found)
            start = found + 1

    return sorted(cuts)


def _segments(text: str) -> list[str]:
    bounds = [0, *_cut_points(text), len(text)]
    pieces = (text[a:b].strip() for a, b in zip(bounds, bounds[1:]))
    return [p for p in pieces if p]


def _pack(pieces: list[str], max_chars: int) -> list[str]:
    """Greedily fill chunks up to max_chars, preserving order."""
    packed: list[str] = []
    current = ""
    for piece in pieces:
        candidate = f"{current} {piece}" if current else piece
        if current and len(candidate) > max_chars:
            packed.append(current)
            current = piece
        else:
            current = candidate
    if current:
        packed.append(current)
    return packed


def _split_section(text: str, max_chars: int) -> list[str]:
    text = text.strip()
    if len(text) <= max_chars:
        return [text]

    chunks: list[str] = []
    for block in _pack(_segments(text), max_chars):
        if len(block) <= max_chars:
            chunks.append(block)
            continue
        # One sub-clause on its own is over budget. Fall back to sentence
        # boundaries. A single sentence longer than max_chars is emitted intact:
        # an oversized chunk is a retrieval nuisance, a severed sentence is a
        # correctness problem.
        chunks.extend(_pack(_SENTENCE.split(block), max_chars))
    return chunks


def build_chunks(*, max_chars: int = 1200) -> list[StatutoryChunk]:
    """Turn ACT_SECTIONS and RULES into embeddable chunks.

    chunk_index restarts at 0 for each section_id and is assigned in reading
    order, so it is stable across runs for a given corpus and max_chars. That
    stability is what lets re-indexing update rows in place instead of colliding
    with the unique constraint on (section_id, chunk_index).
    """
    chunks: list[StatutoryChunk] = []

    for source, provisions in ((SOURCE_ACT, ACT_SECTIONS), (SOURCE_RULES, RULES)):
        for provision in provisions:
            for index, body in enumerate(_split_section(provision.text, max_chars)):
                chunks.append(
                    StatutoryChunk(
                        source=source,
                        section_id=provision.section_id,
                        section_title=provision.title,
                        citation_label=provision.citation_label,
                        chunk_index=index,
                        text=body,
                    )
                )
    return chunks
