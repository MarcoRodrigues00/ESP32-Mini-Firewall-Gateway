# Backlog final

Este backlog organiza os proximos passos ate a entrega e defesa. A ordem prioriza requisitos obrigatorios do TDE e evita aumentar o escopo antes da montagem fisica estar estavel.

## Alta prioridade

1. Revisao visual final do dashboard, demo, gateway, logs e evidencias.
2. Coleta de evidencias finais somente apos grandes avancos.
3. Montagem e teste dos sensores fisicos.
4. Teste fisico real do INA219.
5. Integracao e validacao do DHT22.
6. Integracao e validacao do MQ-2.
7. Integracao de atuadores reais: rele e ventoinha com fonte adequada e GND comum.
8. Validacao de buzzer apenas como apoio, sem contar como um dos dois atuadores principais.
9. Atualizacao do relatorio final conforme comportamento real.
10. Preparacao da apresentacao final e roteiro de fala.

## Media prioridade

1. Revisar documentacao de hardware com fotos e ligacoes reais.
2. Confirmar ausencia de `delay()` indevido antes do commit final.
3. Confirmar que sensores ausentes mostram `n/d` ou indisponivel.
4. Validar persistencia LittleFS antes e depois de reboot.
5. Registrar limitacao caso nao haja janela real de 24 horas para historico.
6. Revisar ABNT, referencias e coerencia entre relatorio e firmware.
7. Rodar smoke test final conectado ao AP do ESP32.

## Baixa prioridade

1. Separar `src/main.cpp` em modulos fisicos se o ganho de manutencao justificar.
2. Melhorar graficos ou series temporais do dashboard.
3. Adicionar pagina de configuracao mais completa.
4. Explorar Light Sleep com cuidado para nao derrubar o AP durante a demo.

## Somente se sobrar tempo

1. Investigar NAT experimental AP+STA.
2. Criar teste de longa duracao para historico de 24 horas.
3. Adicionar display local, se o driver e a pinagem forem confirmados.

## Fora de escopo para a defesa atual

- Firewall profissional de pacotes.
- IDS/IPS completo.
- Inspecao HTTPS.
- WAF.
- SIEM/SOAR.
- Gateway de producao para compartilhar internet.
