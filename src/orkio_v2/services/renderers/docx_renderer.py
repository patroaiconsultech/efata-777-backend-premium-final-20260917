from __future__ import annotations
import io, zipfile
from xml.sax.saxutils import escape
from ..artifact_specs import ArtifactDocumentSpec,HeadingBlock,ParagraphBlock,ListBlock,TableBlock,PageBreakBlock

WNS="http://schemas.openxmlformats.org/wordprocessingml/2006/main"
RNS="http://schemas.openxmlformats.org/officeDocument/2006/relationships"

def _run(text:str,bold:bool=False)->str:
    prop="<w:rPr><w:b/></w:rPr>" if bold else ""
    return f'<w:r>{prop}<w:t xml:space="preserve">{escape(text)}</w:t></w:r>'

def _paragraph(text:str,style:str|None=None,num_id:int|None=None)->str:
    ppr=[]
    if style: ppr.append(f'<w:pStyle w:val="{style}"/>')
    if num_id is not None: ppr.append(f'<w:numPr><w:ilvl w:val="0"/><w:numId w:val="{num_id}"/></w:numPr>')
    ppr_xml=f"<w:pPr>{''.join(ppr)}</w:pPr>" if ppr else ""
    return f"<w:p>{ppr_xml}{_run(text)}</w:p>"

def render_docx(spec:ArtifactDocumentSpec)->bytes:
    body=[]
    for block in spec.blocks:
        if isinstance(block,HeadingBlock):
            body.append(_paragraph(block.text,f"Heading{min(max(block.level,1),3)}"))
        elif isinstance(block,ParagraphBlock):
            body.append(_paragraph(block.text))
        elif isinstance(block,ListBlock):
            num_id=2 if block.ordered else 1
            body.extend(_paragraph(item,num_id=num_id) for item in block.items)
        elif isinstance(block,TableBlock) and block.rows:
            rows=[]
            column_count=max(1,len(block.rows[0]))
            table_width=9900
            column_width=max(1200,table_width//column_count)
            for ridx,row in enumerate(block.rows):
                cells=[]
                for value in row:
                    cells.append(
                        f'<w:tc><w:tcPr><w:tcW w:w="{column_width}" w:type="dxa"/></w:tcPr>'
                        '<w:p>'+_run(value,bold=(ridx==0))+'</w:p></w:tc>'
                    )
                rows.append("<w:tr>"+''.join(cells)+"</w:tr>")
            grid=''.join(f'<w:gridCol w:w="{column_width}"/>' for _ in range(column_count))
            body.append(
                f'<w:tbl><w:tblPr><w:tblStyle w:val="TableGrid"/>'
                f'<w:tblW w:w="{table_width}" w:type="dxa"/>'
                '<w:tblLayout w:type="fixed"/></w:tblPr>'
                f'<w:tblGrid>{grid}</w:tblGrid>'+''.join(rows)+"</w:tbl>"
            )
        elif isinstance(block,PageBreakBlock):
            body.append('<w:p><w:r><w:br w:type="page"/></w:r></w:p>')
    body.append('<w:sectPr><w:headerReference w:type="default" r:id="rIdHeader"/><w:footerReference w:type="default" r:id="rIdFooter"/><w:pgSz w:w="12240" w:h="15840"/><w:pgMar w:top="1008" w:right="1152" w:bottom="1008" w:left="1152" w:header="500" w:footer="500" w:gutter="0"/></w:sectPr>')
    document='<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'+f'<w:document xmlns:w="{WNS}" xmlns:r="{RNS}"><w:body>{"".join(body)}</w:body></w:document>'
    styles="""<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<w:styles xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">
<w:style w:type="paragraph" w:default="1" w:styleId="Normal"><w:name w:val="Normal"/><w:rPr><w:rFonts w:ascii="Aptos" w:hAnsi="Aptos"/><w:sz w:val="21"/></w:rPr><w:pPr><w:spacing w:after="100" w:line="260" w:lineRule="auto"/></w:pPr></w:style>
<w:style w:type="paragraph" w:styleId="Heading1"><w:name w:val="heading 1"/><w:basedOn w:val="Normal"/><w:rPr><w:b/><w:sz w:val="36"/></w:rPr><w:pPr><w:keepNext/><w:spacing w:before="180" w:after="120"/></w:pPr></w:style>
<w:style w:type="paragraph" w:styleId="Heading2"><w:name w:val="heading 2"/><w:basedOn w:val="Normal"/><w:rPr><w:b/><w:sz w:val="30"/></w:rPr><w:pPr><w:keepNext/><w:spacing w:before="160" w:after="100"/></w:pPr></w:style>
<w:style w:type="paragraph" w:styleId="Heading3"><w:name w:val="heading 3"/><w:basedOn w:val="Normal"/><w:rPr><w:b/><w:sz w:val="26"/></w:rPr></w:style>
<w:style w:type="table" w:styleId="TableGrid"><w:name w:val="Table Grid"/><w:tblPr><w:tblBorders><w:top w:val="single" w:sz="4" w:color="AAB4C0"/><w:left w:val="single" w:sz="4" w:color="AAB4C0"/><w:bottom w:val="single" w:sz="4" w:color="AAB4C0"/><w:right w:val="single" w:sz="4" w:color="AAB4C0"/><w:insideH w:val="single" w:sz="4" w:color="AAB4C0"/><w:insideV w:val="single" w:sz="4" w:color="AAB4C0"/></w:tblBorders></w:tblPr></w:style>
</w:styles>"""
    numbering="""<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<w:numbering xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">
<w:abstractNum w:abstractNumId="0"><w:multiLevelType w:val="singleLevel"/><w:lvl w:ilvl="0"><w:start w:val="1"/><w:numFmt w:val="bullet"/><w:lvlText w:val="•"/><w:pPr><w:ind w:left="720" w:hanging="360"/></w:pPr></w:lvl></w:abstractNum>
<w:abstractNum w:abstractNumId="1"><w:multiLevelType w:val="singleLevel"/><w:lvl w:ilvl="0"><w:start w:val="1"/><w:numFmt w:val="decimal"/><w:lvlText w:val="%1."/><w:pPr><w:ind w:left="720" w:hanging="360"/></w:pPr></w:lvl></w:abstractNum>
<w:num w:numId="1"><w:abstractNumId w:val="0"/></w:num><w:num w:numId="2"><w:abstractNumId w:val="1"/></w:num>
</w:numbering>"""
    header=f'<?xml version="1.0" encoding="UTF-8" standalone="yes"?><w:hdr xmlns:w="{WNS}"><w:p><w:pPr><w:jc w:val="right"/></w:pPr>{_run("EFATÀ 777")}</w:p></w:hdr>'
    footer=f'<?xml version="1.0" encoding="UTF-8" standalone="yes"?><w:ftr xmlns:w="{WNS}"><w:p><w:pPr><w:jc w:val="center"/></w:pPr>{_run("EFATÀ 777  •  Página\u00a0")}<w:r><w:fldChar w:fldCharType="begin"/></w:r><w:r><w:instrText xml:space="preserve"> PAGE </w:instrText></w:r><w:r><w:fldChar w:fldCharType="end"/></w:r></w:p></w:ftr>'
    rels=f'<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="{RNS}/officeDocument" Target="word/document.xml"/></Relationships>'
    doc_rels=f'<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rIdStyles" Type="{RNS}/styles" Target="styles.xml"/><Relationship Id="rIdNumbering" Type="{RNS}/numbering" Target="numbering.xml"/><Relationship Id="rIdHeader" Type="{RNS}/header" Target="header1.xml"/><Relationship Id="rIdFooter" Type="{RNS}/footer" Target="footer1.xml"/></Relationships>'
    types='<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/><Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/><Override PartName="/word/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.styles+xml"/><Override PartName="/word/numbering.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.numbering+xml"/><Override PartName="/word/header1.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.header+xml"/><Override PartName="/word/footer1.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.footer+xml"/></Types>'
    out=io.BytesIO()
    with zipfile.ZipFile(out,"w",zipfile.ZIP_DEFLATED) as z:
        z.writestr("[Content_Types].xml",types); z.writestr("_rels/.rels",rels)
        z.writestr("word/document.xml",document); z.writestr("word/_rels/document.xml.rels",doc_rels)
        z.writestr("word/styles.xml",styles); z.writestr("word/numbering.xml",numbering)
        z.writestr("word/header1.xml",header); z.writestr("word/footer1.xml",footer)
    return out.getvalue()
