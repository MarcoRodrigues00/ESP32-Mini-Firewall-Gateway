Execute a Fase 0 do projeto.

Objetivo:
Deixar o projeto PlatformIO compilando com firmware mínimo para ESP32.

Tarefas:
1. Verificar `platformio.ini`.
2. Criar ou ajustar `src/main.cpp`.
3. Fazer firmware mínimo com `Serial.begin`.
4. Evitar `delay()` no fluxo principal. Usar `vTaskDelay` ou controle não bloqueante.
5. Adicionar mensagem de boot clara.
6. Rodar `pio run`.

Não implementar Wi-Fi ainda.
Não implementar dashboard ainda.
Não adicionar bibliotecas desnecessárias.

Ao final, responder no formato obrigatório do `AGENTS.md`.
