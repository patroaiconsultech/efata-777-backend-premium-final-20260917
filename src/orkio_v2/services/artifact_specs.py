from __future__ import annotations
from dataclasses import dataclass
import re
from typing import Literal

@dataclass(frozen=True, slots=True)
class HeadingBlock:
    kind: Literal["heading"]
    text: str
    level: int

@dataclass(frozen=True, slots=True)
class ParagraphBlock:
    kind: Literal["paragraph"]
    text: str

@dataclass(frozen=True, slots=True)
class ListBlock:
    kind: Literal["list"]
    items: tuple[str, ...]
    ordered: bool

@dataclass(frozen=True, slots=True)
class TableBlock:
    kind: Literal["table"]
    rows: tuple[tuple[str, ...], ...]

@dataclass(frozen=True, slots=True)
class PageBreakBlock:
    kind: Literal["page_break"] = "page_break"

ArtifactBlock = HeadingBlock | ParagraphBlock | ListBlock | TableBlock | PageBreakBlock

@dataclass(frozen=True, slots=True)
class ArtifactDocumentSpec:
    title: str
    blocks: tuple[ArtifactBlock, ...]
    semantic_text: str

@dataclass(frozen=True, slots=True)
class SlideSpec:
    title: str
    bullets: tuple[str, ...]

_PAGE_BREAKS={"[[page_break]]","<!-- pagebreak -->","<!-- page-break -->"}
_HEADING_RE=re.compile(r"^(#{1,6})\s+(.+?)\s*$")
_BULLET_RE=re.compile(r"^\s*[-*+]\s+(.+?)\s*$")
_NUMBER_RE=re.compile(r"^\s*\d+[.)]\s+(.+?)\s*$")
_TABLE_SEPARATOR_RE=re.compile(r"^\s*\|?\s*:?-{3,}:?\s*(?:\|\s*:?-{3,}:?\s*)+\|?\s*$")

def _clean(value:str)->str:
    return re.sub(r"\s+"," ",value.strip())

def _split_table_row(line:str)->tuple[str,...]:
    return tuple(_clean(cell) for cell in line.strip().strip("|").split("|"))

def _is_table_start(lines:list[str],index:int)->bool:
    return index+1<len(lines) and "|" in lines[index] and bool(_TABLE_SEPARATOR_RE.match(lines[index+1]))

def parse_document_spec(content:str)->ArtifactDocumentSpec:
    source=(content or "").replace("\r\n","\n").replace("\r","\n").strip()
    if not source:
        return ArtifactDocumentSpec("Documento",(),"")
    lines=source.split("\n")
    blocks:list[ArtifactBlock]=[]
    semantic:list[str]=[]
    title=""
    i=0
    while i<len(lines):
        raw=lines[i]; stripped=raw.strip()
        if not stripped:
            i+=1; continue
        if stripped.lower() in _PAGE_BREAKS:
            blocks.append(PageBreakBlock()); i+=1; continue
        m=_HEADING_RE.match(stripped)
        if m:
            text=_clean(m.group(2)); level=len(m.group(1))
            title=title or text
            blocks.append(HeadingBlock("heading",text,level)); semantic.append(text); i+=1; continue
        if _is_table_start(lines,i):
            rows=[_split_table_row(lines[i])]; i+=2
            while i<len(lines):
                current=lines[i].strip()
                if not current or "|" not in current: break
                rows.append(_split_table_row(lines[i])); i+=1
            cols=max(len(row) for row in rows)
            normalized=tuple(tuple(list(row)+[""]*(cols-len(row))) for row in rows)
            blocks.append(TableBlock("table",normalized))
            semantic.extend(" | ".join(cell for cell in row if cell) for row in normalized)
            continue
        bullet=_BULLET_RE.match(raw); numbered=_NUMBER_RE.match(raw)
        if bullet or numbered:
            ordered=bool(numbered); items=[]
            while i<len(lines):
                match=(_NUMBER_RE if ordered else _BULLET_RE).match(lines[i])
                if not match: break
                item=_clean(match.group(1))
                if item: items.append(item); semantic.append(item)
                i+=1
            if items: blocks.append(ListBlock("list",tuple(items),ordered))
            continue
        para=[stripped]; i+=1
        while i<len(lines):
            cur=lines[i]; s=cur.strip()
            if not s: break
            if (_HEADING_RE.match(s) or _BULLET_RE.match(cur) or _NUMBER_RE.match(cur)
                or s.lower() in _PAGE_BREAKS or _is_table_start(lines,i)):
                break
            para.append(s); i+=1
        text=_clean(" ".join(para))
        if text:
            title=title or text[:120]
            blocks.append(ParagraphBlock("paragraph",text)); semantic.append(text)
    return ArtifactDocumentSpec((title or "Documento")[:160],tuple(blocks),"\n".join(semantic).strip())

def semantic_anchor_text(spec:ArtifactDocumentSpec,*,limit:int=180)->str:
    return re.sub(r"\s+"," ",spec.semantic_text).strip()[:limit]

def _bullet_chunks(text:str,max_chars:int)->list[str]:
    clean=_clean(text)
    if not clean: return []
    if len(clean)<=max_chars: return [clean]
    words=clean.split(); out=[]; current=""
    for word in words:
        candidate=(current+" "+word).strip()
        if current and len(candidate)>max_chars:
            out.append(current); current=word
        else: current=candidate
    if current: out.append(current)
    return out

def build_slide_plan(spec:ArtifactDocumentSpec,*,max_bullets_per_slide:int=6,max_bullet_chars:int=210)->tuple[str,tuple[SlideSpec,...]]:
    sections=[]; current_title="Resumo"; current_items=[]
    def flush():
        nonlocal current_items
        if current_items:
            sections.append((current_title[:100],current_items)); current_items=[]
    for block in spec.blocks:
        if isinstance(block,HeadingBlock):
            if block.level<=2: flush(); current_title=block.text
            else: current_items.append(block.text)
        elif isinstance(block,ParagraphBlock):
            current_items.extend(_bullet_chunks(block.text,max_bullet_chars))
        elif isinstance(block,ListBlock):
            for item in block.items: current_items.extend(_bullet_chunks(item,max_bullet_chars))
        elif isinstance(block,TableBlock) and block.rows:
            header=block.rows[0]
            for row in block.rows[1:]:
                pairs=[f"{header[j]}: {row[j]}" for j in range(min(len(header),len(row))) if header[j] or row[j]]
                if pairs: current_items.append(" | ".join(pairs)[:max_bullet_chars])
        elif isinstance(block,PageBreakBlock): flush()
    flush()
    if not sections and spec.semantic_text:
        sections=[("Resumo",_bullet_chunks(spec.semantic_text,max_bullet_chars))]
    slides=[]
    for stitle,items in sections:
        safe=[item for item in items if item.strip()] or ["Conteúdo"]
        for off in range(0,len(safe),max_bullets_per_slide):
            title=stitle if off==0 else f"{stitle} — continuação"
            slides.append(SlideSpec(title[:100],tuple(safe[off:off+max_bullets_per_slide])))
    return spec.title[:100],tuple(slides)

def spreadsheet_rows(content:str,spec:ArtifactDocumentSpec)->list[list[str]]:
    for block in spec.blocks:
        if isinstance(block,TableBlock) and block.rows:
            return [list(row) for row in block.rows]
    rows=[]
    for raw in (content or "").replace("\r\n","\n").splitlines():
        clean=raw.strip()
        if not clean: continue
        if "\t" in clean: rows.append([_clean(c) for c in clean.split("\t")])
        elif "|" in clean and not _TABLE_SEPARATOR_RE.match(clean): rows.append(list(_split_table_row(clean)))
    if rows: return rows
    rows=[["Tipo","Conteúdo"]]
    for block in spec.blocks:
        if isinstance(block,HeadingBlock): rows.append([f"Título H{block.level}",block.text])
        elif isinstance(block,ParagraphBlock): rows.append(["Parágrafo",block.text])
        elif isinstance(block,ListBlock): rows.extend([["Item",item] for item in block.items])
    return rows
