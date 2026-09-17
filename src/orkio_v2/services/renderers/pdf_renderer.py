from __future__ import annotations
from html import escape
import io
from ..artifact_specs import ArtifactDocumentSpec,HeadingBlock,ParagraphBlock,ListBlock,TableBlock,PageBreakBlock

class PdfRendererUnavailable(RuntimeError): pass

def render_pdf(spec:ArtifactDocumentSpec)->bytes:
    try:
        from reportlab.lib import colors
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.styles import ParagraphStyle,getSampleStyleSheet
        from reportlab.lib.units import mm
        from reportlab.platypus import SimpleDocTemplate,Paragraph,Spacer,Table,TableStyle,ListFlowable,ListItem,PageBreak
    except ImportError as exc:
        raise PdfRendererUnavailable("ARTIFACT_PDF_RENDERER_UNAVAILABLE") from exc
    out=io.BytesIO()
    doc=SimpleDocTemplate(out,pagesize=A4,leftMargin=18*mm,rightMargin=18*mm,topMargin=22*mm,bottomMargin=20*mm,title=spec.title,author="EFATÀ 777")
    styles=getSampleStyleSheet()
    body=ParagraphStyle("EfataBody",parent=styles["BodyText"],fontName="Helvetica",fontSize=9.8,leading=13.2,spaceAfter=6)
    h1=ParagraphStyle("EfataH1",parent=styles["Heading1"],fontName="Helvetica-Bold",fontSize=18,leading=21,spaceAfter=8)
    h2=ParagraphStyle("EfataH2",parent=styles["Heading2"],fontName="Helvetica-Bold",fontSize=14,leading=17,spaceAfter=6)
    h3=ParagraphStyle("EfataH3",parent=styles["Heading3"],fontName="Helvetica-Bold",fontSize=11.5,leading=14,spaceAfter=4)
    story=[]
    for block in spec.blocks:
        if isinstance(block,HeadingBlock):
            story.append(Paragraph(escape(block.text),h1 if block.level==1 else h2 if block.level==2 else h3))
        elif isinstance(block,ParagraphBlock):
            story.append(Paragraph(escape(block.text),body))
        elif isinstance(block,ListBlock):
            items=[ListItem(Paragraph(escape(item),body),leftIndent=8) for item in block.items]
            story.append(ListFlowable(items,bulletType="1" if block.ordered else "bullet",leftIndent=18))
            story.append(Spacer(1,4))
        elif isinstance(block,TableBlock) and block.rows:
            usable=A4[0]-doc.leftMargin-doc.rightMargin
            cols=max(1,len(block.rows[0]))
            data=[[Paragraph(escape(cell),body) for cell in row] for row in block.rows]
            table=Table(data,colWidths=[usable/cols]*cols,repeatRows=1)
            table.setStyle(TableStyle([
                ("BACKGROUND",(0,0),(-1,0),colors.HexColor("#E9EEF5")),
                ("FONTNAME",(0,0),(-1,0),"Helvetica-Bold"),
                ("VALIGN",(0,0),(-1,-1),"TOP"),
                ("GRID",(0,0),(-1,-1),0.35,colors.HexColor("#AAB4C0")),
                ("LEFTPADDING",(0,0),(-1,-1),5),("RIGHTPADDING",(0,0),(-1,-1),5),
            ]))
            story.append(table); story.append(Spacer(1,8))
        elif isinstance(block,PageBreakBlock):
            story.append(PageBreak())
    def header_footer(canvas,built):
        canvas.saveState(); width,height=A4
        canvas.setFont("Helvetica",8); canvas.setFillColorRGB(.35,.39,.45)
        canvas.drawString(doc.leftMargin,height-12*mm,"EFATÀ 777")
        canvas.drawCentredString(width/2,10*mm,f"Página {built.page}")
        canvas.restoreState()
    doc.build(story,onFirstPage=header_footer,onLaterPages=header_footer)
    return out.getvalue()
