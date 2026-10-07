# Sistema de Agendamento UENF
CAIO HENRIQUE DESENVOLVEDOR FULL STACK 

Sistema web desenvolvido em Flask para gerenciamento de agendamentos, requerimentos, equipamentos e empréstimos.

O projeto foi desenvolvido para organizar o fluxo de solicitações de uso de equipamentos e oficinas, permitindo o acompanhamento por usuários, encarregados e administradores.

## Funcionalidades

O sistema possui diferentes níveis de acesso:

### Usuário
- Cadastro e login
- Envio de requerimentos
- Seleção de equipamentos
- Acompanhamento do status dos pedidos
- Visualização dos requerimentos enviados
- Cancelamento de pedidos pendentes
- Exclusão de registros já finalizados

### Encarregado
- Visualização de solicitações relacionadas aos seus equipamentos
- Aprovação ou reprovação de pedidos
- Visualização de empréstimos ativos
- Finalização de empréstimos

### Administrador
- Gerenciamento de usuários
- Gerenciamento de equipamentos
- Visualização de empréstimos ativos
- Aprovação e gerenciamento de solicitações
- Controle dos encarregados

## Tecnologias utilizadas

- Python
- Flask
- SQLite
- HTML
- CSS
- Jinja2

## Estrutura do projeto

```text
Sistema-AgendamentoUENF/
│
├── app.py
├── requirements.txt
├── .gitignore
│
├── static/
│   ├── style.css
│   ├── style_requerimento.css
│   ├── fundo.jpg
│   ├── sua_logo.png
│   ├── intro-desktop.mp4
│   └── intro-mobile.mp4
│
└── templates/
    ├── admin.html
    ├── admin_emprestimos.html
    ├── admin_requerimentos.html
    ├── admin_usuarios.html
    ├── base.html
    ├── cadastro.html
    ├── dashboard.html
    ├── emprestimos.html
    ├── encarregado.html
    ├── ferramentas.html
    ├── login.html
    ├── painel_encarregado.html
    ├── requerimento.html
    ├── selecionar_encarregado.html
    ├── tutorial.html
    ├── usuarios.html
    └── visualizar_requerimento.html