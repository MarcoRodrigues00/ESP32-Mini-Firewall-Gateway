#!/usr/bin/env python3
import html
import os
import shutil
import struct
import zipfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "ESP32_Mini_Firewall_Gateway_apresentacao.pptx"
MEDIA = ROOT / "evidencias" / "prints"
EMU_PER_INCH = 914400
SLIDE_W = 13.333333
SLIDE_H = 7.5


def emu(inches):
    return int(inches * EMU_PER_INCH)


def png_size(path):
    with open(path, "rb") as handle:
        signature = handle.read(24)
    if signature[:8] != b"\x89PNG\r\n\x1a\n":
        raise ValueError(f"Arquivo nao e PNG: {path}")
    width, height = struct.unpack(">II", signature[16:24])
    return width, height


def escape(value):
    return html.escape(str(value), quote=True)


class Slide:
    def __init__(self, title=None, subtitle=None, footer=None):
        self.title = title
        self.subtitle = subtitle
        self.footer = footer
        self.shapes = []

    def add_text(self, text, x, y, w, h, size=24, bold=False, color="1F2937", align="l"):
        self.shapes.append(("text", text, x, y, w, h, size, bold, color, align))

    def add_bullets(self, items, x, y, w, h, size=20, color="263238"):
        self.shapes.append(("bullets", items, x, y, w, h, size, color))

    def add_image(self, name, path, x, y, w, h):
        self.shapes.append(("image", name, path, x, y, w, h))

    def add_band(self, x, y, w, h, color="EAF2F8"):
        self.shapes.append(("band", x, y, w, h, color))


def shape_text(shape_id, text, x, y, w, h, size, bold, color, align):
    bold_tag = '<a:b/>' if bold else ''
    return f"""
    <p:sp>
      <p:nvSpPr><p:cNvPr id="{shape_id}" name="Text {shape_id}"/><p:cNvSpPr txBox="1"/><p:nvPr/></p:nvSpPr>
      <p:spPr><a:xfrm><a:off x="{emu(x)}" y="{emu(y)}"/><a:ext cx="{emu(w)}" cy="{emu(h)}"/></a:xfrm><a:prstGeom prst="rect"><a:avLst/></a:prstGeom><a:noFill/><a:ln><a:noFill/></a:ln></p:spPr>
      <p:txBody>
        <a:bodyPr wrap="square" anchor="t"/>
        <a:lstStyle/>
        <a:p>
          <a:pPr algn="{align}"/>
          <a:r><a:rPr lang="pt-BR" sz="{size * 100}">{bold_tag}<a:solidFill><a:srgbClr val="{color}"/></a:solidFill></a:rPr><a:t>{escape(text)}</a:t></a:r>
        </a:p>
      </p:txBody>
    </p:sp>"""


def shape_bullets(shape_id, items, x, y, w, h, size, color):
    paragraphs = []
    for item in items:
        paragraphs.append(f"""
        <a:p>
          <a:pPr marL="285750" indent="-171450"><a:buChar char="•"/></a:pPr>
          <a:r><a:rPr lang="pt-BR" sz="{size * 100}"><a:solidFill><a:srgbClr val="{color}"/></a:solidFill></a:rPr><a:t>{escape(item)}</a:t></a:r>
        </a:p>""")
    return f"""
    <p:sp>
      <p:nvSpPr><p:cNvPr id="{shape_id}" name="Bullets {shape_id}"/><p:cNvSpPr txBox="1"/><p:nvPr/></p:nvSpPr>
      <p:spPr><a:xfrm><a:off x="{emu(x)}" y="{emu(y)}"/><a:ext cx="{emu(w)}" cy="{emu(h)}"/></a:xfrm><a:prstGeom prst="rect"><a:avLst/></a:prstGeom><a:noFill/><a:ln><a:noFill/></a:ln></p:spPr>
      <p:txBody><a:bodyPr wrap="square" anchor="t"/><a:lstStyle/>{''.join(paragraphs)}</p:txBody>
    </p:sp>"""


def shape_band(shape_id, x, y, w, h, color):
    return f"""
    <p:sp>
      <p:nvSpPr><p:cNvPr id="{shape_id}" name="Band {shape_id}"/><p:cNvSpPr/><p:nvPr/></p:nvSpPr>
      <p:spPr><a:xfrm><a:off x="{emu(x)}" y="{emu(y)}"/><a:ext cx="{emu(w)}" cy="{emu(h)}"/></a:xfrm><a:prstGeom prst="rect"><a:avLst/></a:prstGeom><a:solidFill><a:srgbClr val="{color}"/></a:solidFill><a:ln><a:noFill/></a:ln></p:spPr>
      <p:txBody><a:bodyPr/><a:lstStyle/><a:p/></p:txBody>
    </p:sp>"""


def shape_image(shape_id, rid, name, path, x, y, w, h):
    iw, ih = png_size(path)
    box_ratio = w / h
    image_ratio = iw / ih
    if image_ratio > box_ratio:
        final_w = w
        final_h = w / image_ratio
        final_x = x
        final_y = y + (h - final_h) / 2
    else:
        final_h = h
        final_w = h * image_ratio
        final_x = x + (w - final_w) / 2
        final_y = y
    return f"""
    <p:pic>
      <p:nvPicPr><p:cNvPr id="{shape_id}" name="{escape(name)}"/><p:cNvPicPr><a:picLocks noChangeAspect="1"/></p:cNvPicPr><p:nvPr/></p:nvPicPr>
      <p:blipFill><a:blip r:embed="{rid}"/><a:stretch><a:fillRect/></a:stretch></p:blipFill>
      <p:spPr><a:xfrm><a:off x="{emu(final_x)}" y="{emu(final_y)}"/><a:ext cx="{emu(final_w)}" cy="{emu(final_h)}"/></a:xfrm><a:prstGeom prst="rect"><a:avLst/></a:prstGeom></p:spPr>
    </p:pic>"""


def slide_xml(slide, index, images):
    parts = [
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>',
        '<p:sld xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships" xmlns:p="http://schemas.openxmlformats.org/presentationml/2006/main">',
        '<p:cSld><p:bg><p:bgPr><a:solidFill><a:srgbClr val="FFFFFF"/></a:solidFill><a:effectLst/></p:bgPr></p:bg><p:spTree>',
        '<p:nvGrpSpPr><p:cNvPr id="1" name=""/><p:cNvGrpSpPr/><p:nvPr/></p:nvGrpSpPr><p:grpSpPr><a:xfrm><a:off x="0" y="0"/><a:ext cx="0" cy="0"/><a:chOff x="0" y="0"/><a:chExt cx="0" cy="0"/></a:xfrm></p:grpSpPr>',
        shape_band(2, 0, 0, SLIDE_W, 0.42, "0F766E"),
    ]
    sid = 3
    if slide.title:
        parts.append(shape_text(sid, slide.title, 0.55, 0.62, 12.2, 0.55, 30, True, "102A43", "l"))
        sid += 1
    if slide.subtitle:
        parts.append(shape_text(sid, slide.subtitle, 0.58, 1.18, 12.0, 0.45, 17, False, "52616B", "l"))
        sid += 1
    for shape in slide.shapes:
        if shape[0] == "text":
            _, text, x, y, w, h, size, bold, color, align = shape
            parts.append(shape_text(sid, text, x, y, w, h, size, bold, color, align))
        elif shape[0] == "bullets":
            _, items, x, y, w, h, size, color = shape
            parts.append(shape_bullets(sid, items, x, y, w, h, size, color))
        elif shape[0] == "image":
            _, name, path, x, y, w, h = shape
            rid = images[str(path)]
            parts.append(shape_image(sid, rid, name, path, x, y, w, h))
        elif shape[0] == "band":
            _, x, y, w, h, color = shape
            parts.append(shape_band(sid, x, y, w, h, color))
        sid += 1
    footer = slide.footer or f"ESP32 Mini Firewall Gateway | slide {index}"
    parts.append(shape_text(sid, footer, 0.58, 7.08, 12.1, 0.25, 9, False, "6B7280", "r"))
    parts.extend(['</p:spTree></p:cSld><p:clrMapOvr><a:masterClrMapping/></p:sld>'])
    return "".join(parts)


def rels_xml(entries):
    rels = ['<?xml version="1.0" encoding="UTF-8" standalone="yes"?>',
            '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">']
    for rid, rel_type, target in entries:
        rels.append(f'<Relationship Id="{rid}" Type="{rel_type}" Target="{target}"/>')
    rels.append('</Relationships>')
    return "".join(rels)


def make_slides():
    slides = []

    s = Slide("ESP32 Mini Firewall Gateway", "TDE - Performance de Sistemas Ciberfisicos | estado atual do projeto")
    s.add_text("Projeto academico com ESP32 fisico, Wi-Fi AP e dashboard web embarcado.", 0.72, 2.0, 7.3, 0.8, 28, True, "102A43")
    s.add_bullets([
        "Escopo didatico/de laboratorio",
        "Nao substitui firewall profissional",
        "Versao atual documentada: 0.3.0-fase2",
        "Evidencias registradas em prints e logs no repositorio",
    ], 0.9, 3.0, 6.7, 2.1, 21)
    s.add_image("Dashboard AP", MEDIA / "02_dashboard_ap.png", 8.0, 1.75, 4.6, 3.8)
    slides.append(s)

    s = Slide("Planejamento e Backlog", "Organizacao do trabalho e rastreabilidade")
    s.add_bullets([
        "Backlog do projeto estruturado no Notion para acompanhar fases, requisitos e pendencias",
        "Fases planejadas: setup, AP/dashboard, FreeRTOS/metricas, logs, firewall, sensores, atuadores, energia e documentacao",
        "Uso do backlog para priorizar entregas minimas antes de avancar de fase",
        "Evidencias associadas ao progresso: upload, serial, AP, dashboard e API de status",
    ], 0.9, 1.85, 11.5, 2.8, 22)
    s.add_band(0.85, 5.2, 11.65, 0.92, "E6F4F1")
    s.add_text("Mensagem para a defesa: o Notion apoia a gestao do projeto; os resultados tecnicos apresentados aqui estao evidenciados no firmware, docs, prints e logs do repositorio.", 1.1, 5.37, 11.15, 0.45, 18, False, "0F3D3E")
    slides.append(s)

    s = Slide("O Que Ja Temos", "Fases 0, 1 e 2 implementadas")
    s.add_bullets([
        "Fase 0: firmware minimo PlatformIO, boot serial e heartbeat sem delay()",
        "Fase 1: Wi-Fi AP ESP32-Firewall-Lab, servidor WebServer.h e dashboard com 7 abas",
        "Fase 2: tasks FreeRTOS, snapshot de metricas com mutex e rota /api/status ampliada",
        "Dashboard ja exibe performance basica, Wi-Fi AP, tasks planejadas e tempos medidos",
    ], 0.75, 1.75, 6.1, 3.45, 21)
    s.add_image("Serial boot", MEDIA / "02_serial_boot_fase1.png", 7.1, 1.7, 5.1, 3.95)
    slides.append(s)

    s = Slide("Arquitetura Atual", "Firmware embarcado no ESP32")
    s.add_bullets([
        "Stack: PlatformIO, Arduino C++, WebServer.h sincrono e FreeRTOS nativo",
        "AP obrigatorio ativo em 192.168.4.1",
        "taskWebServer no core 1 atendendo server.handleClient() a cada 10 ms",
        "taskMetrics no core 0 atualizando uptime, heap, flash, sketch e estado do AP",
        "taskHeartbeat no core 0 registrando atividade serial a cada 5 s",
        "Snapshot compartilhado protegido por mutex FreeRTOS",
    ], 0.75, 1.68, 11.8, 4.6, 20)
    slides.append(s)

    s = Slide("Dashboard Web", "Interface embarcada acessada pelo AP local")
    s.add_image("Dashboard home", MEDIA / "04_dashboard_home_fase1.png", 0.72, 1.55, 5.85, 4.9)
    s.add_image("Performance fase 2", MEDIA / "06_performance_fase2.png", 6.75, 1.55, 5.85, 4.9)
    s.add_text("Abas obrigatorias ja aparecem na interface: Performance, Firewall, Clientes, Logs, Configuracao, Sobre e Changelog.", 0.8, 6.55, 11.8, 0.35, 16, False, "374151")
    slides.append(s)

    s = Slide("Metricas da Fase 2", "Dados reais capturados pela API /api/status")
    s.add_bullets([
        "Uptime registrado na evidencia: 159 s",
        "Heap livre: 232920 bytes; heap minimo: 213088 bytes",
        "Flash detectada: 4194304 bytes; sketch: 791280 bytes",
        "AP: SSID ESP32-Firewall-Lab e IP 192.168.4.1",
        "Tempo medido: buildStatusJson 384 us; handleRoot 24770 us",
    ], 0.75, 1.7, 5.6, 3.5, 20)
    s.add_image("API status fase 2", MEDIA / "07_api_status_fase2.png", 6.55, 1.65, 5.85, 3.0)
    s.add_text("Observacao: tres tempos de funcao ainda aparecem como pendentes e devem ser refinados nas proximas fases.", 6.75, 5.25, 5.4, 0.75, 17, False, "6B3F00")
    slides.append(s)

    s = Slide("Evidencias Registradas", "Provas do funcionamento ja capturadas")
    s.add_image("Upload success", MEDIA / "01_upload_success.png", 0.65, 1.45, 5.65, 3.2)
    s.add_image("Wi-Fi AP", MEDIA / "03_wifi_ap_fase1.png", 6.8, 1.65, 4.6, 0.95)
    s.add_image("API fase 1", MEDIA / "05_api_status_fase1.png", 6.35, 3.05, 5.25, 2.35)
    s.add_bullets([
        "Upload do firmware",
        "Boot e heartbeat no monitor serial",
        "AP Wi-Fi visivel",
        "Dashboard web acessivel",
        "JSON de status das fases 1 e 2",
    ], 0.9, 5.05, 5.55, 1.35, 18)
    slides.append(s)

    s = Slide("Aderencia Parcial ao TDE", "Itens atendidos ate a Fase 2")
    s.add_bullets([
        "Sistema baseado em ESP32 fisico com firmware C++/Arduino",
        "Interface web embarcada funcionando no proprio dispositivo",
        "Wi-Fi AP obrigatorio implementado",
        "Mais de uma task FreeRTOS criada e documentada no status",
        "Metricas iniciais de performance: uptime, heap, flash, sketch, AP e tempos de funcao",
        "Changelog acessivel pela interface e mantido no repositorio",
    ], 0.75, 1.7, 11.8, 4.2, 21)
    slides.append(s)

    s = Slide("Pendencias Tecnicas", "Itens ainda nao concluidos")
    s.add_bullets([
        "Logs INFO/WARN/ERROR/SECURITY com exportacao",
        "Persistencia em LittleFS e configuracao em NVS/Preferences",
        "Firewall didatico: rate limit, blocklist, allowlist e contencao",
        "Sensores fisicos: INA219 e DHT22 ou DS18B20",
        "Atuadores fisicos: rele e cooler com fonte adequada e GND comum",
        "Botao com interrupcao hardware e ISR minima",
        "Modo ECO/gerenciamento de energia",
        "Historico de 24 horas ou limitacao documentada com teste parcial",
    ], 0.75, 1.55, 11.85, 4.95, 19)
    slides.append(s)

    s = Slide("Proximos Passos", "Sequencia recomendada para reduzir risco")
    s.add_bullets([
        "1. Implementar logs e persistencia antes de expandir o firewall",
        "2. Medir stack high watermark e completar cinco funcoes principais",
        "3. Validar sensores ausentes sem derrubar o sistema",
        "4. Integrar rele/cooler com cuidado eletrico e evidencias fisicas",
        "5. Implementar modo ECO e documentar trade-off de latencia/consumo",
        "6. Atualizar relatorio ABNT, plano de testes e evidencias da defesa",
    ], 0.85, 1.75, 11.6, 4.4, 21)
    s.add_band(0.85, 6.15, 11.6, 0.55, "FFF4E5")
    s.add_text("Limite importante: ate agora o projeto esta na Fase 2; os itens acima sao backlog, nao resultado testado.", 1.05, 6.29, 11.2, 0.26, 15, True, "7C2D12")
    slides.append(s)

    return slides


def write_pptx(slides):
    if OUT.exists():
        OUT.unlink()

    image_paths = []
    for slide in slides:
        for shape in slide.shapes:
            if shape[0] == "image":
                image_paths.append(shape[2])
    unique_images = list(dict.fromkeys(image_paths))
    media_names = {str(path): f"image{idx + 1}.png" for idx, path in enumerate(unique_images)}

    with zipfile.ZipFile(OUT, "w", compression=zipfile.ZIP_DEFLATED) as z:
        z.writestr("[Content_Types].xml", content_types(len(slides), len(unique_images)))
        z.writestr("_rels/.rels", rels_xml([
            ("rId1", "http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument", "ppt/presentation.xml"),
            ("rId2", "http://schemas.openxmlformats.org/package/2006/relationships/metadata/core-properties", "docProps/core.xml"),
            ("rId3", "http://schemas.openxmlformats.org/officeDocument/2006/relationships/extended-properties", "docProps/app.xml"),
        ]))
        z.writestr("docProps/core.xml", core_xml())
        z.writestr("docProps/app.xml", app_xml(len(slides)))
        z.writestr("ppt/presentation.xml", presentation_xml(len(slides)))
        z.writestr("ppt/_rels/presentation.xml.rels", presentation_rels(len(slides)))
        z.writestr("ppt/slideMasters/slideMaster1.xml", slide_master_xml())
        z.writestr("ppt/slideMasters/_rels/slideMaster1.xml.rels", rels_xml([
            ("rId1", "http://schemas.openxmlformats.org/officeDocument/2006/relationships/slideLayout", "../slideLayouts/slideLayout1.xml")
        ]))
        z.writestr("ppt/slideLayouts/slideLayout1.xml", slide_layout_xml())
        z.writestr("ppt/slideLayouts/_rels/slideLayout1.xml.rels", rels_xml([
            ("rId1", "http://schemas.openxmlformats.org/officeDocument/2006/relationships/slideMaster", "../slideMasters/slideMaster1.xml")
        ]))
        z.writestr("ppt/theme/theme1.xml", theme_xml())

        for idx, slide in enumerate(slides, start=1):
            image_rids = {}
            rel_entries = [("rId1", "http://schemas.openxmlformats.org/officeDocument/2006/relationships/slideLayout", "../slideLayouts/slideLayout1.xml")]
            next_rid = 2
            for shape in slide.shapes:
                if shape[0] == "image":
                    path = str(shape[2])
                    if path not in image_rids:
                        image_rids[path] = f"rId{next_rid}"
                        rel_entries.append((f"rId{next_rid}", "http://schemas.openxmlformats.org/officeDocument/2006/relationships/image", f"../media/{media_names[path]}"))
                        next_rid += 1
            z.writestr(f"ppt/slides/slide{idx}.xml", slide_xml(slide, idx, image_rids))
            z.writestr(f"ppt/slides/_rels/slide{idx}.xml.rels", rels_xml(rel_entries))

        for path in unique_images:
            z.write(path, f"ppt/media/{media_names[str(path)]}")


def content_types(slide_count, image_count):
    overrides = [
        '<Override PartName="/ppt/presentation.xml" ContentType="application/vnd.openxmlformats-officedocument.presentationml.presentation.main+xml"/>',
        '<Override PartName="/ppt/slideMasters/slideMaster1.xml" ContentType="application/vnd.openxmlformats-officedocument.presentationml.slideMaster+xml"/>',
        '<Override PartName="/ppt/slideLayouts/slideLayout1.xml" ContentType="application/vnd.openxmlformats-officedocument.presentationml.slideLayout+xml"/>',
        '<Override PartName="/ppt/theme/theme1.xml" ContentType="application/vnd.openxmlformats-officedocument.theme+xml"/>',
        '<Override PartName="/docProps/core.xml" ContentType="application/vnd.openxmlformats-package.core-properties+xml"/>',
        '<Override PartName="/docProps/app.xml" ContentType="application/vnd.openxmlformats-officedocument.extended-properties+xml"/>',
    ]
    for i in range(1, slide_count + 1):
        overrides.append(f'<Override PartName="/ppt/slides/slide{i}.xml" ContentType="application/vnd.openxmlformats-officedocument.presentationml.slide+xml"/>')
    return f'''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
<Default Extension="xml" ContentType="application/xml"/>
<Default Extension="png" ContentType="image/png"/>
{''.join(overrides)}
</Types>'''


def core_xml():
    return '''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties" xmlns:dc="http://purl.org/dc/elements/1.1/" xmlns:dcterms="http://purl.org/dc/terms/" xmlns:dcmitype="http://purl.org/dc/dcmitype/" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
<dc:title>ESP32 Mini Firewall Gateway - Apresentacao</dc:title>
<dc:subject>TDE Performance de Sistemas Ciberfisicos</dc:subject>
<dc:creator>Projeto ESP32 Mini Firewall Gateway</dc:creator>
<cp:lastModifiedBy>Projeto ESP32 Mini Firewall Gateway</cp:lastModifiedBy>
</cp:coreProperties>'''


def app_xml(slide_count):
    return f'''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Properties xmlns="http://schemas.openxmlformats.org/officeDocument/2006/extended-properties" xmlns:vt="http://schemas.openxmlformats.org/officeDocument/2006/docPropsVTypes">
<Application>OpenXML</Application><PresentationFormat>Widescreen</PresentationFormat><Slides>{slide_count}</Slides>
</Properties>'''


def presentation_xml(slide_count):
    slides = "".join([f'<p:sldId id="{255 + i}" r:id="rId{i}"/>' for i in range(1, slide_count + 1)])
    return f'''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<p:presentation xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships" xmlns:p="http://schemas.openxmlformats.org/presentationml/2006/main">
<p:sldMasterIdLst><p:sldMasterId id="2147483648" r:id="rId{slide_count + 1}"/></p:sldMasterIdLst>
<p:sldIdLst>{slides}</p:sldIdLst>
<p:sldSz cx="{emu(SLIDE_W)}" cy="{emu(SLIDE_H)}" type="wide"/>
<p:notesSz cx="6858000" cy="9144000"/>
</p:presentation>'''


def presentation_rels(slide_count):
    entries = []
    for i in range(1, slide_count + 1):
        entries.append((f"rId{i}", "http://schemas.openxmlformats.org/officeDocument/2006/relationships/slide", f"slides/slide{i}.xml"))
    entries.append((f"rId{slide_count + 1}", "http://schemas.openxmlformats.org/officeDocument/2006/relationships/slideMaster", "slideMasters/slideMaster1.xml"))
    entries.append((f"rId{slide_count + 2}", "http://schemas.openxmlformats.org/officeDocument/2006/relationships/theme", "theme/theme1.xml"))
    return rels_xml(entries)


def slide_master_xml():
    return '''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<p:sldMaster xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships" xmlns:p="http://schemas.openxmlformats.org/presentationml/2006/main">
<p:cSld><p:spTree><p:nvGrpSpPr><p:cNvPr id="1" name=""/><p:cNvGrpSpPr/><p:nvPr/></p:nvGrpSpPr><p:grpSpPr><a:xfrm><a:off x="0" y="0"/><a:ext cx="0" cy="0"/><a:chOff x="0" y="0"/><a:chExt cx="0" cy="0"/></a:xfrm></p:grpSpPr></p:spTree></p:cSld>
<p:clrMap bg1="lt1" tx1="dk1" bg2="lt2" tx2="dk2" accent1="accent1" accent2="accent2" accent3="accent3" accent4="accent4" accent5="accent5" accent6="accent6" hlink="hlink" folHlink="folHlink"/>
<p:sldLayoutIdLst><p:sldLayoutId id="2147483649" r:id="rId1"/></p:sldLayoutIdLst>
</p:sldMaster>'''


def slide_layout_xml():
    return '''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<p:sldLayout xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships" xmlns:p="http://schemas.openxmlformats.org/presentationml/2006/main" type="blank" preserve="1">
<p:cSld name="Blank"><p:spTree><p:nvGrpSpPr><p:cNvPr id="1" name=""/><p:cNvGrpSpPr/><p:nvPr/></p:nvGrpSpPr><p:grpSpPr><a:xfrm><a:off x="0" y="0"/><a:ext cx="0" cy="0"/><a:chOff x="0" y="0"/><a:chExt cx="0" cy="0"/></a:xfrm></p:grpSpPr></p:spTree></p:cSld>
<p:clrMapOvr><a:masterClrMapping/></p:clrMapOvr>
</p:sldLayout>'''


def theme_xml():
    return '''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<a:theme xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main" name="ESP32">
<a:themeElements>
<a:clrScheme name="ESP32"><a:dk1><a:srgbClr val="102A43"/></a:dk1><a:lt1><a:srgbClr val="FFFFFF"/></a:lt1><a:dk2><a:srgbClr val="1F2937"/></a:dk2><a:lt2><a:srgbClr val="F4F6F8"/></a:lt2><a:accent1><a:srgbClr val="0F766E"/></a:accent1><a:accent2><a:srgbClr val="2563EB"/></a:accent2><a:accent3><a:srgbClr val="F59E0B"/></a:accent3><a:accent4><a:srgbClr val="DC2626"/></a:accent4><a:accent5><a:srgbClr val="4B5563"/></a:accent5><a:accent6><a:srgbClr val="16A34A"/></a:accent6><a:hlink><a:srgbClr val="2563EB"/></a:hlink><a:folHlink><a:srgbClr val="7C3AED"/></a:folHlink></a:clrScheme>
<a:fontScheme name="Arial"><a:majorFont><a:latin typeface="Arial"/></a:majorFont><a:minorFont><a:latin typeface="Arial"/></a:minorFont></a:fontScheme>
<a:fmtScheme name="Default"><a:fillStyleLst><a:solidFill><a:schemeClr val="phClr"/></a:solidFill></a:fillStyleLst><a:lnStyleLst><a:ln w="9525"><a:solidFill><a:schemeClr val="phClr"/></a:solidFill></a:ln></a:lnStyleLst><a:effectStyleLst><a:effectStyle><a:effectLst/></a:effectStyle></a:effectStyleLst><a:bgFillStyleLst><a:solidFill><a:schemeClr val="phClr"/></a:solidFill></a:bgFillStyleLst></a:fmtScheme>
</a:themeElements>
</a:theme>'''


def main():
    slides = make_slides()
    write_pptx(slides)
    print(OUT)


if __name__ == "__main__":
    main()
