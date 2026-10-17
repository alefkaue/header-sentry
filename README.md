# header-sentry

[![Tests](https://github.com/alefkaue/header-sentry/actions/workflows/tests.yml/badge.svg)](https://github.com/alefkaue/header-sentry/actions/workflows/tests.yml)

Auditoria offline de cabeçalhos HTTP. Projeto independente de portfólio voltado a **AppSec / análise de configuração**.

Analisa cabeçalhos HTTP exportados, sem enviar requisições a servidores.
    Identifica ausência ou configuração fraca de CSP, HSTS, proteção contra framing,
    X-Content-Type-Options e Referrer-Policy, com recomendações específicas.

## Executar

Requer Python 3.11 ou superior. Usa somente a biblioteca padrão; não precisa instalar pacotes.

```console
git clone https://github.com/alefkaue/header-sentry.git
cd header-sentry
python header_sentry.py examples/headers.txt --https
```

As ferramentas escrevem JSON em stdout. Use `--help` para consultar opções. Exemplos são sintéticos e não contêm dados reais.

O exemplo com `--https` retorna quatro regras: `missing_csp`, `framing`, `referrer_policy` e `hsts`. `nosniff` já está configurado. O código de saída é **1**, indicando achados. Sem `--https`, HSTS não é avaliado.

## Testes

```console
python -m unittest discover -s tests -v
```

A automação executa a suíte em Windows e Linux, com Python 3.11 e 3.13.

## Decisões e limites

Veja [a arquitetura](docs/architecture.md) para o modelo de ameaça, decisões e limitações. Este é um laboratório educacional: os resultados exigem contexto e validação humana. Não substitui um SIEM, EDR ou avaliação completa de segurança.

## Exercício para demonstração

Execute o exemplo, explique cada campo do JSON e altere a entrada para observar a mudança no resultado. Os testes documentam casos de detecção e de comportamento esperado.

## Desenvolvimento

Código inicial desenvolvido com assistência de IA. O repositório explicita o escopo e usa dados sintéticos para permitir revisão e reprodução. Sugestões e correções podem ser propostas por issues e pull requests. Licença MIT.
