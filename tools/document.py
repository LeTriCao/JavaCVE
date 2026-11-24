"""Small dependency-free DOCX renderer for generated Vietnamese course reports."""
from xml.sax.saxutils import escape
from zipfile import ZipFile, ZIP_DEFLATED


def paragraph(text,style=None):
    properties = '<w:pPr><w:pStyle w:val="'+style+'"/></w:pPr>' if style else ""
    return '<w:p>'+properties+'<w:r><w:t xml:space="preserve">'+escape(text)+'</w:t></w:r></w:p>'


def docx(markdown,path):
    body = []
    for line in markdown.splitlines():
        if line.startswith("|"):
            cells = [c.strip().replace("`","") for c in line.strip("|").split("|")]
            if all(set(c)<={"-",":"," "} for c in cells):
                continue
            body.append('<w:tbl><w:tblPr><w:tblW w:w="0" w:type="auto"/></w:tblPr><w:tr>'+"".join('<w:tc>'+paragraph(c)+'</w:tc>' for c in cells)+'</w:tr></w:tbl>')
        else:
            level = len(line)-len(line.lstrip("#"))
            style = "Title" if level==1 else "Heading1" if level>1 else None
            body.append(paragraph(line.lstrip("# ").replace("`",""),style))
    document = '<?xml version="1.0" encoding="UTF-8" standalone="yes"?><w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:body>'+"".join(body)+'<w:sectPr><w:pgSz w:w="11906" w:h="16838"/><w:pgMar w:top="1134" w:right="1134" w:bottom="1134" w:left="1417"/></w:sectPr></w:body></w:document>'
    with ZipFile(path,"x",compression=ZIP_DEFLATED) as archive:
        archive.writestr("[Content_Types].xml",'<?xml version="1.0" encoding="UTF-8"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/><Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/><Override PartName="/word/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.styles+xml"/></Types>')
        archive.writestr("_rels/.rels",'<?xml version="1.0"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/></Relationships>')
        archive.writestr("word/document.xml",document)
        archive.writestr("word/_rels/document.xml.rels",'<?xml version="1.0"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles" Target="styles.xml"/></Relationships>')
        archive.writestr("word/styles.xml",'<?xml version="1.0"?><w:styles xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:docDefaults><w:rPrDefault><w:rPr><w:rFonts w:ascii="Times New Roman" w:hAnsi="Times New Roman"/><w:sz w:val="26"/></w:rPr></w:rPrDefault></w:docDefaults><w:style w:type="paragraph" w:styleId="Title"><w:name w:val="Title"/><w:rPr><w:b/><w:sz w:val="36"/></w:rPr></w:style><w:style w:type="paragraph" w:styleId="Heading1"><w:name w:val="Heading 1"/><w:rPr><w:b/><w:sz w:val="30"/></w:rPr></w:style></w:styles>')
