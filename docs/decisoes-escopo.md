# Decisoes de escopo

Este documento registra decisoes tecnicas e limitacoes assumidas para manter a sprint alinhada ao TDE, ao hardware disponivel e ao prazo.

## NAT real nao implementado nesta fase

O firmware mostra telemetria AP+STA, mas nao implementa NAT/roteamento real como requisito desta sprint. O ESP32 mantem o AP local e pode tentar STA upstream quando configurado, porem a entrega atual nao deve ser apresentada como compartilhamento de internet nem gateway de producao.

Motivo: NAT funcional no ESP32 aumenta risco tecnico, exige validacao de rede mais profunda e pode consumir tempo que e mais importante para requisitos obrigatorios do TDE, como interface embarcada, logs, metricas, persistencia, sensores e defesa academica.

## IDS didatico baseado em HTTP do painel

O IDS atual observa eventos relacionados ao servidor web embarcado: flood didatico, rotas inexistentes e caminhos sensiveis simulados. A rota `/demo/ids` gera uma assinatura controlada para apresentacao.

Motivo: essa abordagem e verificavel em bancada, nao depende de ataque real e permite explicar conceitos de deteccao sem prometer IDS/IPS completo.

## Sem inspecao HTTPS

O projeto nao inspeciona HTTPS. O ESP32 atende um painel HTTP local e nao faz interceptacao, descriptografia ou analise de trafego criptografado.

Motivo: inspecao HTTPS exigiria arquitetura e responsabilidades fora do escopo academico atual.

## Sensores fisicos ficam para fase final

Sensores fisicos adicionais, como DHT22 e MQ-2, ficam para a fase final. Eles dependem de montagem correta, ligacao em bancada, alimentacao adequada, eventual solda e teste fisico.

Motivo: a documentacao nao deve tratar sensores nao montados como concluidos. Quando o sensor estiver ausente, o sistema deve mostrar `n/d` ou indisponivel e registrar aviso quando aplicavel.

## INA219 preparado, teste fisico depende de montagem

O firmware ja possui preparacao para INA219 e trata ausencia do sensor sem derrubar o sistema. O teste fisico completo, porem, depende do modulo real ligado corretamente ao barramento I2C e ao circuito de medicao.

Motivo: corrente, tensao e potencia so podem ser validadas com hardware montado. Nao se deve inventar leitura nem apresentar valor simulado como real.

## LittleFS com politica seletiva

Os logs persistentes usam LittleFS em `/events.log` com politica seletiva. Eventos relevantes sao persistidos, enquanto acessos comuns ao painel permanecem apenas em RAM.

Motivo: reduzir escrita desnecessaria na flash e manter evidencias importantes apos reboot sem transformar cada request em operacao de arquivo.

## Smoke test no lugar de prints excessivos durante desenvolvimento

O smoke tester `tools/smoke_test_http.py` valida paginas, APIs e rotas demo de forma repetivel. Ele ajuda a evitar colecao de prints a cada microteste.

Motivo: evidencias finais devem ser coletadas nos grandes avancos e na montagem fisica. Durante desenvolvimento, teste automatizado leve da mais confianca e menos ruido.

## Firewall nao substitui firewall profissional

O firewall da sprint e didatico e limitado aos acessos HTTP do painel. Ele registra contadores, ultima rota, ultimo IP e eventos de flood controlado.

Ele nao substitui pfSense, OPNsense, Mikrotik, Fortinet, roteador real, IDS/IPS, WAF, SIEM ou solucao profissional. Tambem nao filtra trafego geral de uma rede nem promete protecao contra ataques reais.

Motivo: o objetivo do TDE e demonstrar um sistema ciberfisico real com metricas, interface embarcada, logs, persistencia e conceitos de seguranca de forma honesta e verificavel.

## Configuracao upstream sem NAT real

A configuracao de Wi-Fi upstream foi adicionada para facilitar a demonstracao em bancada e permitir trocar a rede externa sem regravar firmware. A decisao de escopo e manter AP+STA como telemetria e conectividade didatica, sem implementar NAT real nesta sprint.

A configuracao fica em LittleFS (`/wifi.json`) porque o projeto ja inicializa esse filesystem e a necessidade e simples. A passphrase e necessaria localmente para conectar a STA, mas nao e exposta em pagina, API, eventos, Serial ou relatorios do smoke test.

Nao ha autenticacao nessa fase. Por isso, `/wifi`, `/wifi/save`, `/wifi/clear` e `/wifi/reconnect` devem ser usados apenas no AP local de laboratorio. Autenticacao fica para sprint futura se houver tempo e necessidade.

## NAT experimental com fallback

A decisao desta sprint e tentar NAT de forma experimental, sem transformar o projeto em roteador profissional. A feature flag `NAT_EXPERIMENTAL_ENABLED` permite desligar a tentativa caso gere instabilidade.

O core instalado foi inspecionado localmente: ha headers de NAPT no lwIP, mas o `sdkconfig` do pacote nao habilita IP forward e a biblioteca precompilada pode nao exportar os simbolos NAPT. Por isso, o firmware trata suporte como condicional e documenta `nao suportado` quando necessario, em vez de quebrar o boot.

NAT depende de upstream conectado, IP valido e suporte do core/lwIP. Mesmo quando ativo, desempenho e estabilidade sao limitados e nao substituem roteador/firewall profissional.

## Traffic Monitor v0.1 na main

A branch `main` passa a ter `/traffic`, `/api/traffic` e `/demo/scan` para reforcar a aparencia de mini appliance portatil de seguranca. A implementacao e propositalmente leve, em RAM, sem dependencia externa e baseada no `WebServer.h` sincronico ja usado pelo projeto.

A decisao de escopo e nao implementar sniffing/promiscuous mode nesta sprint. O objetivo e demonstrar telemetria HTTP do painel, eventos IDS didaticos e logs persistentes, mantendo estabilidade do TDE. NAT real continua separado na PoC ESP-IDF.

## Relatorio de evidencia sem PDF embarcado

A sprint adiciona `/report` e `/api/report` para consolidar evidencias diretamente no ESP32. A decisao e manter HTML/JSON simples, sem gerar PDF no microcontrolador e sem dependencia externa.

O relatorio nao muda o escopo de seguranca: o monitoramento HTTP segue didatico, nao ha sniffing, nao ha inspecao HTTPS e a PoC de NAT real permanece separada na branch ESP-IDF experimental.
