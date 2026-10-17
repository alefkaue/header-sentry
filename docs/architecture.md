# Arquitetura e limites

A entrada é um único bloco de resposta HTTP em texto, com linha de status opcional. Nomes são normalizados sem descartar duplicatas. A análise gera regras identificáveis e recomendações em JSON. Retorno CLI: 0 sem achados, 1 com achados, 2 erro de leitura/formato. Para coletar em um sistema autorizado: curl -sS -D headers.txt -o /dev/null https://seu-dominio.example (em PowerShell use curl.exe e -o NUL). Inspecione o arquivo e mantenha somente um bloco de resposta.

O modelo é heurístico e direcionado a páginas HTML. Não avalia corpo, cookies, TLS, redirecionamentos ou CSP completa; não calcula nota de segurança nem certifica ausência de vulnerabilidades. Duplicatas exigem revisão manual. CSP permite políticas complexas, nonces, hashes e interações entre diretivas que não são interpretadas integralmente. O limite de HSTS é uma política deste laboratório, não uma exigência universal. Ative --https somente para resposta HTTPS. Conteúdo da entrada não é executado nem enviado à rede.

Próxima evolução: parser estruturado de CSP com corpus de políticas e exportação SARIF.
