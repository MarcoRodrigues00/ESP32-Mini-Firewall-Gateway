# AGENTS.md — ESP32 Mini Firewall Gateway

## Projeto

Nome:
ESP32 Mini Firewall Gateway

Tipo:
TDE acadêmico da disciplina Performance de Sistemas Ciberfísicos.

Objetivo:
Construir um sistema ciberfísico real, físico e funcional, baseado em ESP32, com interface web embarcada, métricas de performance, logs, configuração dinâmica, persistência, gerenciamento de energia, sensores, atuadores, FreeRTOS e documentação acadêmica.

Este projeto é didático/de laboratório.
Não é firewall profissional.
Não substitui pfSense, OPNsense, Mikrotik, Fortinet, IDS/IPS, WAF, SIEM ou roteador real.

## Requisitos obrigatórios do TDE

O projeto precisa cumprir:

1. Sistema ciberfísico real baseado em ESP32.
2. Não usar simulador, emulador ou entrega exclusivamente virtual.
3. Interface web embarcada no próprio sistema.
4. Guia única de Performance contendo:
   - uso de CPU;
   - uso de memória: heap, stack, flash e PSRAM quando aplicável;
   - tempo de execução de no mínimo cinco funções principais;
   - dados dos sensores;
   - informações de tasks/threads;
   - estado da conexão Wi-Fi e do ponto de acesso;
   - gráficos de performance, séries temporais e uso de recursos.
5. Sistema de logs com:
   - erro;
   - warning;
   - informação;
   - exportação dos logs.
6. Área de configuração via interface web:
   - frequência de leitura dos sensores;
   - parâmetros operacionais;
   - configuração/troca do ponto de acesso Wi-Fi sem regravar firmware.
7. Guia Sobre contendo:
   - nome da universidade;
   - nome completo dos integrantes;
   - e-mail de contato;
   - link para GitHub.
8. Guia Changelog acessível pela interface gráfica.
9. Persistência com histórico mínimo de 24 horas.
10. Proibição de rotinas bloqueantes, especialmente `delay()` no fluxo principal.
11. Uso de mais de uma task.
12. Uso de interrupção de hardware.
13. Gerenciamento de energia com Light Sleep ou Deep Sleep.
14. Linguagem C/C++ ou MicroPython. Este projeto usa C++/Arduino.
15. Código versionado em repositório público GitHub.
16. Mínimo de dois sensores de entrada.
17. Mínimo de dois dispositivos de acionamento, que não podem ser LEDs nem buzzers.
18. Sistema acondicionado em caixa física apropriada.
19. Montagem organizada, segura e funcional.
20. Sistema entregue fisicamente montado e funcionando.
21. Documentação acadêmica conforme ABNT.
22. Defesa técnica e originalidade.

## Stack definida

- ESP32 físico.
- PlatformIO.
- Framework Arduino.
- C++.
- `WebServer.h` síncrono.
- FreeRTOS nativo do Arduino-ESP32.
- LittleFS para histórico/logs.
- NVS/Preferences para configuração.
- Wi-Fi AP obrigatório.
- Wi-Fi STA opcional.
- Dashboard local sem CDN obrigatório.

## Hardware previsto

- ESP32 com display, se o driver for confirmado.
- INA219 para corrente/tensão.
- DHT22 ou DS18B20 para temperatura.
- Botão físico para interrupção.
- Relé 5V.
- Cooler 5V.
- Fonte 5V externa.
- Protoboard.
- Jumpers.
- Caixa física.

## Arquitetura alvo

Módulos sugeridos:

- `wifi_manager`
- `web_server`
- `metrics`
- `firewall`
- `clients`
- `logs`
- `storage`
- `config`
- `sensors`
- `actuators`
- `power`
- `button`
- `display` opcional

Tasks sugeridas:

- `taskWebServer`
- `taskFirewall`
- `taskSensors`
- `taskActuators`
- `taskMetrics`
- `taskPersistence`
- `taskPower`

Usar `xTaskCreatePinnedToCore` quando possível.

## Regras obrigatórias de implementação

1. Não usar `delay()` no fluxo principal.
2. Usar `vTaskDelay`, timers ou controle por `millis()`.
3. ISR deve ser mínima.
4. ISR deve usar `IRAM_ATTR`.
5. ISR não pode usar:
   - `Serial`;
   - `String`;
   - `malloc`;
   - escrita em arquivo;
   - JSON;
   - Wi-Fi;
   - chamadas lentas.
6. ISR deve apenas sinalizar evento para uma task.
7. Sensores ausentes não podem derrubar o sistema.
8. Sensor com falha deve gerar WARN e mostrar `n/d`.
9. Cooler nunca deve ser ligado direto no GPIO.
10. Relé/cooler devem usar fonte adequada e GND comum.
11. Configuração sensível não deve devolver senha em texto claro.
12. Histórico e logs precisam evitar escrita excessiva em flash.
13. Cada fase precisa compilar antes de avançar.
14. Não implementar funcionalidades grandes sem necessidade do TDE.
15. Não inventar hardware que não existe na bancada.
16. Não simular valor de sensor como se fosse real.
17. Se algo estiver em stub, deixar explícito no código, dashboard e docs.
18. Nunca inventar resultado de teste.
19. Nunca afirmar que um teste passou se ele não foi executado.
20. Ao final de cada tarefa, explicar como testar.

## O que não pode no projeto

Não pode:

- usar simulador como entrega principal;
- depender de Wokwi;
- depender só de prints sem hardware real;
- usar LED/buzzer como os dois atuadores principais;
- ligar cooler direto no GPIO;
- prometer firewall profissional;
- dizer que substitui pfSense, OPNsense, Mikrotik ou Fortinet;
- prometer inspeção HTTPS;
- prometer IDS/IPS completo;
- prometer WAF real;
- prometer SIEM/SOAR;
- prometer NAT AP↔STA como requisito obrigatório;
- usar `delay()` no fluxo principal;
- deixar o sistema travar se sensor falhar;
- remover requisitos do TDE sem registrar limitação;
- criar código copiado de tutorial sem adaptação/autoria;
- deixar documentos mencionando IA, Claude, ChatGPT, Cowork, Codex ou ferramenta geradora;
- colocar segredos reais no GitHub;
- subir `.env`, tokens ou senhas reais;
- mascarar erro como sucesso;
- inventar testes;
- dizer que há histórico 24h se não foi testado ou documentado como parcial.

## Dashboard obrigatório

Abas:

1. Performance
2. Firewall
3. Clientes
4. Logs
5. Configuração
6. Sobre
7. Changelog

Aba Performance deve concentrar:

- uptime;
- heap livre;
- heap mínimo;
- stack high watermark por task quando disponível;
- flash/LittleFS;
- PSRAM quando aplicável;
- tempo de execução de pelo menos cinco funções;
- sensores;
- estado Wi-Fi AP/STA;
- gráficos ou séries temporais.

## Firewall didático

Implementar como mecanismo didático sobre o servidor web e clientes do AP.

Funcionalidades:

- rate limit por IP;
- blocklist;
- allowlist;
- modo contenção;
- logs SECURITY;
- contadores;
- exportação de logs.

Limitação obrigatória:
O sistema não inspeciona tráfego HTTPS e não substitui firewall profissional.

## Logs obrigatórios

Níveis:

- INFO
- WARN
- ERROR
- SECURITY

Eventos mínimos:

- boot;
- Wi-Fi AP iniciado;
- cliente acessou;
- rate limit excedido;
- IP bloqueado;
- contenção ligada/desligada;
- falha de sensor;
- alteração de configuração;
- exportação de logs.

## Persistência

Usar:

- NVS/Preferences para configuração.
- LittleFS para logs e histórico.

Obrigatório:
Histórico mínimo de 24 horas ou implementação preparada com teste parcial e limitação documentada, caso o prazo impeça rodar 24h antes da defesa.

## Energia

Implementar pelo menos:

- modo Normal;
- modo ECO com `WiFi.setSleep(true)` ou estratégia equivalente;
- documentação clara do trade-off entre latência, throughput e autonomia.

Light Sleep é desejável.
Deep Sleep pode ser fora de escopo se derrubar o AP.

## Documentação obrigatória

Criar/manter:

- `README.md`
- `CHANGELOG.md`
- `docs/ARQUITETURA.md`
- `docs/TESTES.md`
- `docs/HARDWARE.md`
- `docs/HARDENING.md`
- `docs/RUNBOOK.md`
- `docs/RELATORIO_BASE.md`
- `docs/REFERENCIAS.md`
- `evidencias/`

Documentação deve ser em português do Brasil, clara, sem marketing e sem promessas exageradas.

## Política de commits

Antes de cada commit:

1. `pio run` precisa passar.
2. Não pode haver `delay()` indevido.
3. Não pode haver segredo real.
4. Não pode haver menção a IA, Claude, ChatGPT, Cowork, Codex ou ferramenta geradora nos arquivos finais.
5. README e docs devem continuar coerentes.
6. Se mexer em requisito do TDE, atualizar documentação.

Sugestões de commit:

- `feat: add esp32 access point`
- `feat: add performance dashboard`
- `feat: add firewall rate limit`
- `feat: add sensor readings`
- `docs: add test plan`
- `fix: handle missing temperature sensor`

## Fases de trabalho

Fase 0 — setup e build mínimo.
Fase 1 — Wi-Fi AP e dashboard base.
Fase 2 — FreeRTOS e métricas.
Fase 3 — logs e persistência.
Fase 4 — firewall didático.
Fase 5 — botão, ISR, relé e cooler.
Fase 6 — sensores.
Fase 7 — energia.
Fase 8 — documentação, testes e evidências.
Fase 9 — polimento e defesa.

Em cada fase:

- implementar o mínimo funcional;
- compilar;
- testar;
- registrar evidência;
- atualizar docs;
- só então avançar.

## Revisões obrigatórias

O Codex deve fazer revisões simulando estes papéis quando solicitado:

### firmware_reviewer

Verificar:

- arquitetura do firmware;
- FreeRTOS;
- ausência de `delay()`;
- ISR mínima;
- uso de mutex/queue/notificação;
- risco de travamento;
- RAM/flash;
- sensores ausentes;
- build PlatformIO.

### tde_requirements_reviewer

Verificar:

- aderência ao TDE;
- requisitos obrigatórios;
- itens eliminatórios;
- interface web;
- logs;
- persistência;
- energia;
- sensores;
- atuadores;
- documentação.

### safety_hardware_reviewer

Verificar:

- cooler não está no GPIO;
- relé adequado;
- fonte externa;
- GND comum;
- sensores ligados corretamente;
- montagem segura;
- caixa física.

### docs_abnt_reviewer

Verificar:

- estrutura acadêmica;
- clareza;
- ABNT;
- referências;
- limitações honestas;
- nada de menção a IA/ferramentas;
- coerência entre texto e firmware real.

### test_evidence_reviewer

Verificar:

- prints;
- vídeos;
- logs exportados;
- testes isolados;
- testes de integração;
- testes de performance;
- evidências suficientes para defesa.

### scope_guardian

Verificar:

- se a tarefa ajuda na rubrica;
- se aumenta demais o escopo;
- se deve manter, cortar ou adiar;
- se há alternativa mínima viável.

## Formato obrigatório de resposta após cada tarefa

Ao final de cada implementação ou revisão, responder com:

1. O que foi alterado.
2. Arquivos modificados.
3. Como testar.
4. Resultado do `pio run`.
5. Requisitos do TDE atendidos.
6. Riscos ou limitações restantes.
7. Próximo passo recomendado.

Se não rodou teste ou build, dizer claramente:
"Não rodei teste/build."

Nunca inventar resultado de teste.
