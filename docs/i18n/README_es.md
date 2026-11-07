<div align="center">

[Türkçe](README_tr.md) · [English](../../README.md) · [Русский](README_ru.md) · [Deutsch](README_de.md) · [Français](README_fr.md) · **Español** · [Português](README_pt.md) · [Italiano](README_it.md) · [Українська](README_uk.md) · [日本語](README_ja.md) · [简体中文](README_zh.md) · [한국어](README_ko.md) · [العربية](README_ar.md)

# permwatch

**Descubre a qué puede acceder cada app de tu Mac.**

Cámara, micrófono, grabación de pantalla, ítems de inicio.<br>
permwatch registra cada cambio de permisos y te avisa en cuanto algo no cuadra.

[![build](https://github.com/cybertoxin3/permwatch/actions/workflows/build.yml/badge.svg)](https://github.com/cybertoxin3/permwatch/actions/workflows/build.yml)
![macOS](https://img.shields.io/badge/macOS-13%2B-black?logo=apple)
![estado](https://img.shields.io/badge/estado-en%20desarrollo-orange)

</div>

---

## Lo permitiste y lo olvidaste

«Permitir grabación de pantalla». «Se requiere acceso de accesibilidad». «¿Abrir al iniciar sesión?»

Pulsamos «Aceptar» decenas de veces al día. Pero ¿a qué app le diste qué permiso, y cuándo?
¿Cuál se añadió en silencio al inicio? macOS no te muestra las respuestas.

**permwatch, sí.**

<p align="center">
  <img src="../images/timeline_es.png" alt="Cronología de permwatch" width="900">
</p>

## Un escenario

Descargas un conversor de PDF gratuito. Lo abres, te pide algunos permisos y pulsas «Aceptar».
Todo parece normal.

Mientras tanto, permwatch ve esto en segundo plano:

| Hora | Qué pasó |
|---|---|
| 13:46 | Se **eliminó la marca de cuarentena** de la app descargada: Gatekeeper quedó esquivado |
| 13:47 | Una app **sin firma** se ejecutó por primera vez desde Descargas |
| 13:48 | En un minuto obtuvo **accesibilidad** y **grabación de pantalla** |
| 13:49 | **Añadió al inicio un programa de una carpeta oculta** |
| 03:12 | A medianoche, mientras dormías, **ese programa oculto se ejecutó** |

Por separado, cada paso parece inofensivo. Juntos forman una cadena de ataque conocida.
permwatch une los puntos y te muestra una sola alerta clara.

<p align="center">
  <img src="../images/alert_es.png" alt="Notificación y barra de menús de permwatch" width="900">
</p>

## Qué hace

- 🕒 **Cronología:** cada cambio de permisos y cada nuevo ítem de inicio, con su fecha y el proceso responsable
- 🚨 **Alertas inteligentes:** apps sin firma, actividad de madrugada, intentos de esquivar Gatekeeper
- 🔍 **Vista por app:** todos los permisos de una app en una sola tarjeta
- 🧬 **Comprobación de firma:** ¿Apple, un desarrollador conocido o una fuente desconocida?
- 📍 **En la barra de menús:** no molesta, pero habla cuando importa

<p align="center">
  <img src="../images/apps_es.png" alt="Vista de apps de permwatch" width="900">
</p>

## Tu privacidad se queda contigo

permwatch **no envía ningún dato.** Sin analíticas, sin cuentas, sin nube.
Todo se queda en tu Mac. Es lo mínimo que esperarías de una herramienta de privacidad.

## Cómo funciona

permwatch usa **Endpoint Security**, el framework oficial de Apple para software de seguridad.
El núcleo está escrito en C. Solo **observa** y nunca interfiere con el funcionamiento del sistema.

## Estado

permwatch está en desarrollo activo.

- ✅ Motor que captura eventos (línea de comandos)
- ⏳ Permiso de Endpoint Security de Apple: solicitado, en revisión
- 🛠 App para macOS e interfaz: en diseño

> Las imágenes de arriba son vistas previas del diseño. «Konvertix» es una app ficticia.

¿Eres desarrollador y quieres probar el núcleo? **[Guía para desarrolladores (en inglés) →](../GELISTIRME_en.md)**

---

<div align="center">
<sub>Hecho por alguien apasionado por la seguridad de macOS, para los curiosos.</sub>
</div>
