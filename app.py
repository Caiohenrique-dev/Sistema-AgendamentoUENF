from flask import Flask, render_template, request, redirect, session, flash, url_for
import sqlite3
import os
import secrets
import hmac
from pathlib import Path
from functools import wraps
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash

BASE_DIR = Path(__file__).resolve().parent
DB_FILE = BASE_DIR / "sistema.db"
SECRET_FILE = BASE_DIR / ".secret_key"

app = Flask(__name__)


def carregar_secret_key():
    chave_ambiente = os.environ.get("SECRET_KEY")
    if chave_ambiente:
        return chave_ambiente

    if SECRET_FILE.exists():
        chave = SECRET_FILE.read_text(encoding="utf-8").strip()
        if chave:
            return chave

    chave = secrets.token_hex(32)
    try:
        SECRET_FILE.write_text(chave, encoding="utf-8")
    except OSError:
        pass

    return chave


app.secret_key = carregar_secret_key()


def senha_esta_hasheada(valor):
    if not valor:
        return False

    return (
        valor.startswith("scrypt:")
        or valor.startswith("pbkdf2:")
    )


def verificar_senha(senha_salva, senha_digitada):
    if not senha_salva or senha_digitada is None:
        return False

    if senha_esta_hasheada(senha_salva):
        try:
            return check_password_hash(senha_salva, senha_digitada)
        except (ValueError, TypeError):
            return False

    return hmac.compare_digest(str(senha_salva), str(senha_digitada))

# ----------------------

# conexão com banco d dados

# -------------------------

def conectar():

    conn = sqlite3.connect(DB_FILE)

    conn.row_factory = sqlite3.Row

    return conn

# -------------------------

# criação d tabelas

# -------------------------

def criar_tabelas():

    with conectar() as conn:

        c = conn.cursor()

        # usuários

        c.execute("""

            CREATE TABLE IF NOT EXISTS usuarios (

                id INTEGER PRIMARY KEY AUTOINCREMENT,

                nome TEXT,

                email TEXT,

                usuario TEXT UNIQUE,

                senha TEXT,

                perfil TEXT,

                subunidade TEXT

            )

        """)

        # pedidos

        c.execute("""

            CREATE TABLE IF NOT EXISTS pedidos (

                id INTEGER PRIMARY KEY AUTOINCREMENT,

                usuario_id INTEGER,

                nome_aluno TEXT,

                email_aluno TEXT,

                matricula TEXT,

                instituicao_responsavel TEXT,

                telefone_instituicao TEXT,

                tipo_projeto TEXT,

                nome_oficina TEXT,

                titulo_projeto TEXT,

                agencia_fomento TEXT,

                ensaios_executar TEXT,

                numero_amostras TEXT,

                periodo TEXT,

                observacoes_requerimento TEXT,

                tecnicos TEXT,

                endereco TEXT,

                bairro_cep TEXT,

                cidade_estado TEXT,

                telefone_contato TEXT,

                email_contato TEXT,

                observacoes_gerais TEXT,

                assinatura_aluno TEXT,

                data_assinatura_aluno TEXT,

                assinatura_supervisor TEXT,

                data_assinatura_supervisor TEXT,

                data_envio TEXT,

                tipo_ensaio TEXT,

                equipamento TEXT,

                data_agendada TEXT,

                hora_inicio TEXT,

                hora_fim TEXT,

                status TEXT DEFAULT 'pendente_encarregado',

                data_emprestimo TEXT,

                data_devolucao TEXT,

                subunidade TEXT,

                encarregado_id INTEGER,

                data_decisao TEXT

            )

        """)

        # empréstimos

        c.execute("""

            CREATE TABLE IF NOT EXISTS emprestimos (

                id INTEGER PRIMARY KEY AUTOINCREMENT,

                pedido_id INTEGER,

                equipamento TEXT,

                encarregado_id INTEGER,

                usuario_id INTEGER,

                data_inicio TEXT,

                data_fim TEXT,

                status TEXT DEFAULT 'ativo'

            )

        """)

        # ferramentas

        c.execute("""

            CREATE TABLE IF NOT EXISTS ferramentas (

                id INTEGER PRIMARY KEY AUTOINCREMENT,

                numero TEXT,

                subunidade TEXT,

                encarregado TEXT,

                equipamento TEXT

            )

        """)

        # admin padrão
        c.execute("SELECT 1 FROM usuarios WHERE usuario = 'admin'")
        if not c.fetchone():

            senha_admin = os.environ.get("ADMIN_PASSWORD")

            if not senha_admin:
                senha_admin = secrets.token_urlsafe(12)
                print("=" * 60)
                print("ADMIN CRIADO")
                print("Usuário: admin")
                print(f"Senha inicial: {senha_admin}")
                print("Guarde esta senha. Ela não fica salva em texto puro.")
                print("=" * 60)

            c.execute("""
                INSERT INTO usuarios (nome, email, usuario, senha, perfil)
                VALUES (?, ?, ?, ?, ?)
            """, (
                "Administrador",
                "admin@email.com",
                "admin",
                generate_password_hash(senha_admin),
                "admin"
            ))

        conn.commit()

# -------------------------

# decorators

# -------------------------

def somente_logado(f):

    @wraps(f)

    def decorated(*args, **kwargs):

        if "usuario_id" not in session:

            flash("Faça login.")

            return redirect(url_for("login"))

        return f(*args, **kwargs)

    return decorated

def somente_admin(f):

    @wraps(f)

    def decorated(*args, **kwargs):

        if session.get("perfil") != "admin":

            flash("Acesso restrito.")

            return redirect(url_for("dashboard"))

        return f(*args, **kwargs)

    return decorated

def somente_encarregado(f):

    @wraps(f)

    def decorated(*args, **kwargs):

        if session.get("perfil") != "encarregado":

            flash("Acesso restrito.")

            return redirect(url_for("dashboard"))

        return f(*args, **kwargs)

    return decorated

def somente_encarregado_ou_admin_enc(f):

    @wraps(f)

    def decorated(*args, **kwargs):

        is_encarregado = session.get("perfil") == "encarregado"

        is_admin_selected = session.get("perfil") == "admin" and session.get("encarregado_id") is not None

        if not (is_encarregado or is_admin_selected):

            flash("Acesso restrito.")

            return redirect(url_for("login"))

        if session.get("perfil") == "admin" and session.get("encarregado_id") is None:

              return redirect(url_for("selecionar_encarregado"))

        return f(*args, **kwargs)

    return decorated

# -------------------------

# login , logout e o cadastro

# -------------------------

@app.route("/")

def index():

    return redirect(url_for("login"))

@app.route("/login", methods=["GET","POST"])

def login():

    if request.method == "POST":

        # Essa variável agora recebe tanto o usuário quanto o email

        usuario_login = request.form["usuario"] 

        senha_login = request.form["senha"]

        with conectar() as conn:
            c = conn.cursor()
            c.execute("""
                SELECT * FROM usuarios
                WHERE usuario=? OR email=?
            """, (usuario_login, usuario_login))
            u = c.fetchone()

            if not u or not verificar_senha(u["senha"], senha_login):
                flash("Usuário, e-mail ou senha incorretos.")
                return render_template("login.html")

            # converte automaticamente senhas antigas em texto puro
            # para hash no primeiro login.
            if not senha_esta_hasheada(u["senha"]):
                nova_senha_hash = generate_password_hash(senha_login)
                c.execute(
                    "UPDATE usuarios SET senha=? WHERE id=?",
                    (nova_senha_hash, u["id"])
                )
                conn.commit()

        # --- login de sucesso ---

        session.clear()

        session["usuario_id"] = u["id"]

        session["nome"] = u["nome"]

        session["perfil"] = u["perfil"]

        # triagem automatica

        # 1. se for ENCARREGADO

        if u["perfil"] == "encarregado":

            session["encarregado_id"] = u["id"] 

            flash(f"Bem-vindo, Encarregado {u['nome']}!")

            return redirect(url_for("painel_encarregado"))

        # 2. se for ADMIN

        elif u["perfil"] == "admin":

            session["encarregado_id"] = None

            return redirect(url_for("admin"))

        # 3. se for ALUNO (Comum)

        else:

            return redirect(url_for("dashboard"))

    return render_template("login.html")

@app.route("/logout")

def logout():

    session.clear()

    return redirect(url_for("login"))

@app.route("/cadastro", methods=["GET","POST"])

def cadastro():

    if request.method=="POST":

        nome = request.form.get("nome")

        email = request.form.get("email")

        usuario = request.form.get("usuario")

        senha = request.form.get("senha")

        if not all([nome, email, usuario, senha]):
            flash("Preencha todos os campos.")
            return render_template("cadastro.html")

        senha_hash = generate_password_hash(senha)

        try:
            with conectar() as conn:
                c = conn.cursor()
                c.execute(
                    "INSERT INTO usuarios (nome,email,usuario,senha,perfil) VALUES (?,?,?,?,?)",
                    (nome, email, usuario, senha_hash, "usuario")
                )

                conn.commit()

            flash("Cadastro realizado!")

            return redirect(url_for("login"))

        except sqlite3.IntegrityError:

            flash("Usuário já existe!")

    return render_template("cadastro.html")

# -------------------------

# Dashboard e requerimentos

# -------------------------

@app.route("/dashboard")

@somente_logado

def dashboard():

    user_id = session["usuario_id"]

    with conectar() as conn:

        c = conn.cursor()

        c.execute("SELECT * FROM pedidos WHERE usuario_id=? ORDER BY id DESC", (user_id,))

        pedidos = c.fetchall()

    return render_template("dashboard.html", pedidos=pedidos)

@app.route("/requerimento", methods=["GET", "POST"])

@somente_logado

def requerimento():

    if request.method == "GET":

        with conectar() as conn:

            c = conn.cursor()

            # aqui rola a busca dinamica (JOIN)

            # pega a ferramenta e cruza com a tabela de usuários para achar o ID do encarregado

            c.execute("""

                SELECT 

                    f.equipamento, 

                    f.encarregado as nome_encarregado, 

                    u.id as id_encarregado

                FROM ferramentas f

                LEFT JOIN usuarios u ON f.encarregado = u.nome

                ORDER BY f.equipamento

            """)

            dados_brutos = c.fetchall()

        # prepara a lista para o HTML

        lista_ferramentas_display = []

        for linha in dados_brutos:

            # se não achou o usuário (u.id for null), avisa no log ou deixa vazio

            nome = linha["nome_encarregado"]

            if not linha["id_encarregado"]:

                nome = "ERRO: Encarregado não tem usuário criado"

            lista_ferramentas_display.append({

                "nome": linha["equipamento"],

                "encarregado": nome,

                "encarregado_id": linha["id_encarregado"] # importante para validação futura se quiser

            })

        return render_template("requerimento.html", lista_ferramentas=lista_ferramentas_display)

    # =========================

    # post + salvar pedido

    # =========================

    if request.method == "POST":

        user_id = session["usuario_id"]

        data_envio = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        equipamento_escolhido = request.form.get("equipamento")

        # 1. busca no BD quem é o encarregado dessa ferramenta

        with conectar() as conn:

            c = conn.cursor()

            c.execute("""

                SELECT f.subunidade, u.id as encarregado_id

                FROM ferramentas f

                JOIN usuarios u ON f.encarregado = u.nome

                WHERE f.equipamento = ?

            """, (equipamento_escolhido,))

            resultado = c.fetchone()

        if not resultado:

            flash(f"Erro: Não foi possível localizar o encarregado da ferramenta '{equipamento_escolhido}'. Verifique se o nome do encarregado na ferramenta é idêntico ao nome do usuário.")

            return redirect(url_for("requerimento"))

        subunidade = resultado["subunidade"]

        encarregado_id = resultado["encarregado_id"]

        # 2. insere o pedido

        with conectar() as conn:

            c = conn.cursor()

            c.execute("""

            INSERT INTO pedidos (

                usuario_id, nome_aluno, email_aluno, matricula, instituicao_responsavel,

                telefone_instituicao, tipo_projeto, nome_oficina, titulo_projeto, agencia_fomento,

                ensaios_executar, numero_amostras, periodo, observacoes_requerimento, tecnicos,

                endereco, bairro_cep, cidade_estado, telefone_contato, email_contato,

                observacoes_gerais, assinatura_aluno, data_assinatura_aluno, assinatura_supervisor,

                data_assinatura_supervisor, data_envio, tipo_ensaio, equipamento, data_agendada,

                hora_inicio, hora_fim, status, subunidade, encarregado_id

            ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)

            """, (

                user_id, request.form.get("nome_aluno"), request.form.get("email_aluno"),

                request.form.get("matricula"), request.form.get("instituicao_responsavel"),

                request.form.get("telefone_instituicao"), request.form.get("tipo_projeto"),

                request.form.get("nome_oficina"), request.form.get("titulo_projeto"),

                request.form.get("agencia_fomento"), request.form.get("ensaios_executar"),

                request.form.get("numero_amostras"), request.form.get("periodo"),

                request.form.get("observacoes_requerimento"), request.form.get("tecnicos"),

                request.form.get("endereco"), request.form.get("bairro_cep"),

                request.form.get("cidade_estado"), request.form.get("telefone_contato"),

                request.form.get("email_contato"), request.form.get("observacoes_gerais"),

                request.form.get("assinatura_aluno"), request.form.get("data_assinatura_aluno"),

                request.form.get("assinatura_supervisor"), request.form.get("data_assinatura_supervisor"),

                data_envio, request.form.get("tipo_ensaio"), equipamento_escolhido,

                request.form.get("data_agendada"), request.form.get("hora_inicio"),

                request.form.get("hora_fim"),

                "pendente_encarregado",

                subunidade,

                encarregado_id

            ))

            conn.commit()

        flash("Requerimento enviado com sucesso!")

        return redirect(url_for("dashboard"))

# -------------------------

# rotas admin e encarregado

# -------------------------

# admin

# -------------------------

@app.route("/selecionar_encarregado", methods=["GET","POST"])

@somente_admin

def selecionar_encarregado():

    with conectar() as conn:

        c = conn.cursor()

        c.execute("SELECT id, nome FROM usuarios WHERE perfil='encarregado' ORDER BY nome")

        encarregados = c.fetchall()

    if request.method == "POST":

        enc_id = request.form.get("encarregado_id")

        if not enc_id:

            flash("Selecione um encarregado.")

            return redirect(url_for("selecionar_encarregado"))

        with conectar() as conn:

            c = conn.cursor()

            c.execute("SELECT nome FROM usuarios WHERE id=?", (enc_id,))

            enc = c.fetchone()

        session["encarregado_id"] = enc_id

        session["encarregado_nome"] = enc["nome"]

        flash(f"Modo de administração ativado para o encarregado: {enc['nome']}")

        return redirect(url_for("admin"))

    return render_template("selecionar_encarregado.html", encarregados=encarregados)

@app.route("/admin")

@somente_logado

@somente_admin

def admin():

    with conectar() as conn:

        c = conn.cursor()

        c.execute("""

            SELECT 

                e.id, 

                e.equipamento, 

                e.data_inicio, 

                u.nome AS nome_aluno, 

                enc.nome AS nome_encarregado

            FROM emprestimos e

            JOIN usuarios u ON u.id = e.usuario_id

            JOIN usuarios enc ON enc.id = e.encarregado_id

            WHERE e.status = 'ativo'

            ORDER BY e.data_inicio DESC

        """)

        emprestimos = c.fetchall()

    return render_template("admin.html", emprestimos=emprestimos)

@app.route("/admin/usuarios")

@somente_logado

@somente_admin

def admin_usuarios():

    with conectar() as conn:

        c = conn.cursor()

        c.execute("SELECT id, nome, usuario, perfil FROM usuarios")

        usuarios = c.fetchall()

    return render_template("admin_usuarios.html", usuarios=usuarios)

@app.route("/admin/usuarios/excluir/<int:id>")

@somente_logado

@somente_admin

def excluir_usuario(id):

    # proteção extra: impede excluir o próprio admin logado para não se trancar fora

    if id == session.get("usuario_id"):

        flash("Você não pode excluir a si mesmo.")

        return redirect(url_for("admin_usuarios"))

    with conectar() as conn:

        c = conn.cursor()

        c.execute("DELETE FROM usuarios WHERE id=?", (id,))

        conn.commit()

    flash("Usuário excluído.")

    return redirect(url_for("admin_usuarios"))

# -------------------------

# PEDIDOS - Admin aprovar/recusar

# -------------------------

@app.route("/pedido/aprovar/<int:id>")

@somente_logado

@somente_admin

def pedido_aprovar(id):

    with conectar() as conn:

        c = conn.cursor()

        # Atualiza pedido como emprestado

        c.execute("UPDATE pedidos SET status='emprestado', data_emprestimo=date('now') WHERE id=?", (id,))

        # Inserir na tabela emprestimos

        c.execute("SELECT usuario_id, equipamento, encarregado_id FROM pedidos WHERE id=?", (id,))

        pedido = c.fetchone()

        if pedido:

            c.execute("""

                INSERT INTO emprestimos (pedido_id, equipamento, encarregado_id, usuario_id, data_inicio, status)

                VALUES (?, ?, ?, ?, ?, ?)

            """, (id, pedido["equipamento"], pedido["encarregado_id"], pedido["usuario_id"], datetime.now().strftime("%Y-%m-%d %H:%M:%S"), "ativo"))

        conn.commit()

    flash("Pedido aprovado e enviado para empréstimos!")

    return redirect(url_for("admin"))

@app.route("/pedido/recusar/<int:id>")

@somente_logado

@somente_admin

def pedido_recusar(id):

    with conectar() as conn:

        c = conn.cursor()

        c.execute("UPDATE pedidos SET status='recusado' WHERE id=?", (id,))

        conn.commit()

    flash("Pedido recusado!")

    return redirect(url_for("admin"))

@app.route("/pedido/devolver/<int:id>")

@somente_logado

@somente_admin

def pedido_devolver(id):

    with conectar() as conn:

        c = conn.cursor()

        # Atualizar pedido e empréstimos como finalizado

        c.execute("UPDATE pedidos SET status='finalizado', data_devolucao=date('now') WHERE id=?", (id,))

        c.execute("UPDATE emprestimos SET status='finalizado', data_fim=date('now') WHERE pedido_id=? AND status='ativo'", (id,))

        conn.commit()

    flash("Empréstimo finalizado com sucesso!")

    return redirect(url_for("admin_emprestimos"))

@app.route("/admin/requerimento/<int:id>")

@somente_logado

def visualizar_requerimento(id):

    # Verifica quem é o usuário

    perfil = session.get("perfil")

    user_id = session.get("usuario_id")

    enc_id = session.get("encarregado_id")

    with conectar() as conn:

        c = conn.cursor()

        c.execute("""

            SELECT p.*, u.nome AS solicitante, u.email AS email_usuario 

            FROM pedidos p

            LEFT JOIN usuarios u ON u.id = p.usuario_id

            WHERE p.id=?

        """, (id,))

        pedido = c.fetchone()

    if not pedido:

        flash("Requerimento não encontrado.")

        return redirect(url_for("dashboard"))

    # SEGURANÇA:

    # 1. admin pode ver tudo.

    # 2. encarregado só pode ver se o pedido for para ele.

    # 3. O próprio usuário (aluno) pode ver seu próprio pedido.

    pode_ver = False

    if perfil == 'admin':

        pode_ver = True

    elif perfil == 'encarregado' and pedido['encarregado_id'] == enc_id:

        pode_ver = True

    elif pedido['usuario_id'] == user_id:

        pode_ver = True

    if not pode_ver:

        flash("Você não tem permissão para visualizar este detalhe.")

        return redirect(url_for("dashboard"))

    return render_template("visualizar_requerimento.html", pedido=pedido)

# #ferramentas - Admin

# -------------------------

@app.route("/admin/ferramentas")

@somente_logado

@somente_admin

def listar_ferramentas():

    with conectar() as conn:

        c = conn.cursor()

        # 1. Busca as ferramentas cadastradas

        c.execute("SELECT * FROM ferramentas ORDER BY id DESC")

        ferramentas = c.fetchall()

        # 2. Busca os encarregados para preencher o formulário de cadastro (dropdown)

        c.execute("SELECT id, nome FROM usuarios WHERE perfil='encarregado' ORDER BY nome")

        encarregados = c.fetchall()

    return render_template("ferramentas.html", ferramentas=ferramentas, encarregados=encarregados)

@app.route("/admin/ferramentas/adicionar", methods=["POST"])

@somente_logado

@somente_admin

def adicionar_ferramenta():

    numero = request.form.get("numero").strip()

    subunidade = request.form.get("subunidade").strip()

    encarregado_nome = request.form.get("encarregado").strip() # Pega do <select>

    equipamento = request.form.get("equipamento").strip()

    if not all([numero, subunidade, encarregado_nome, equipamento]):

        flash("Todos os campos são obrigatórios!")

        return redirect(url_for("listar_ferramentas"))

    with conectar() as conn:

        c = conn.cursor()

        c.execute("INSERT INTO ferramentas (numero, subunidade, encarregado, equipamento) VALUES (?,?,?,?)",

                  (numero, subunidade, encarregado_nome, equipamento))

        conn.commit()

    flash("Ferramenta adicionada com sucesso!")

    return redirect(url_for("listar_ferramentas"))

@app.route("/admin/ferramentas/excluir/<int:id>")

@somente_logado

@somente_admin

def excluir_ferramenta(id):

    with conectar() as conn:

        c = conn.cursor()

        c.execute("DELETE FROM ferramentas WHERE id=?", (id,))

        conn.commit()

    flash("Ferramenta excluída.")

    return redirect(url_for("listar_ferramentas"))

# -------------------------

# emprestimos - Admin

# -------------------------

@app.route("/emprestimo/finalizar/<int:id>")

@somente_logado

@somente_admin

def finalizar_emprestimo_admin(id):

    with conectar() as conn:

        c = conn.cursor()

        # Atualiza status do empréstimo

        c.execute("""

            UPDATE emprestimos

            SET status='finalizado', data_fim=?

            WHERE id=? AND status='ativo'

        """, (datetime.now().strftime("%Y-%m-%d %H:%M:%S"), id))

        # Atualiza status do pedido

        c.execute("""

            UPDATE pedidos

            SET status='finalizado', data_devolucao=?

            WHERE id=(SELECT pedido_id FROM emprestimos WHERE id=?)

        """, (datetime.now().strftime("%Y-%m-%d %H:%M:%S"), id))

        conn.commit()

    flash("Empréstimo finalizado com sucesso!")

    return redirect(url_for("admin_emprestimos"))

@app.route("/admin/emprestimos")

@somente_logado

@somente_admin

def admin_emprestimos():

    with conectar() as conn:

        c = conn.cursor()

        # Seleciona apenas empréstimos ativos

        c.execute("""

            SELECT e.id, e.pedido_id, e.equipamento, e.data_inicio, u.nome AS nome_aluno

            FROM emprestimos e

            JOIN usuarios u ON u.id = e.usuario_id

            WHERE e.status='ativo'

            ORDER BY e.data_inicio DESC

        """)

        emprestimos = c.fetchall()

    return render_template("admin_emprestimos.html", emprestimos=emprestimos)

# -------------------------

# encarregados

# -------------------------

@app.route("/painel_encarregado")

@somente_logado

@somente_encarregado_ou_admin_enc

def painel_encarregado():

    enc_id = session.get("encarregado_id")

    if not enc_id:

        flash("Selecione um encarregado para gerenciar.")

        return redirect(url_for("selecionar_encarregado"))

    with conectar() as conn:

        c = conn.cursor()

        c.execute("""

            SELECT p.*, u.nome AS nome_aluno_solicitante

            FROM pedidos p

            JOIN usuarios u ON u.id = p.usuario_id

            WHERE p.encarregado_id=? AND p.status='pendente_encarregado'

            ORDER BY p.id DESC

        """, (enc_id,))

        pedidos = c.fetchall()

    return render_template("encarregado.html", pedidos=pedidos)

@app.route("/pedido_encarregado/<int:id>/<acao>")

@somente_logado

@somente_encarregado_ou_admin_enc

def decidir_pedido_encarregado(id, acao):

    enc_id = session.get("encarregado_id")  # os id do encarregado Ativo

    with conectar() as conn:

        c = conn.cursor()

        # verifica se o pedido realmente pertence ao encarregado

        c.execute("SELECT * FROM pedidos WHERE id=? AND encarregado_id=?", (id, enc_id))

        pedido = c.fetchone()

        if not pedido:

            flash("Pedido não encontrado ou não pertence a você.", "error")

            return redirect(url_for("painel_encarregado"))

        if acao == "aprovar":

            novo_status = "emprestado"  # o sttatus do pedido aprovado

            flash_msg = "Pedido aprovado e equipamento movido para a lista de empréstimos ativos."

            # aqui ele insere na tabela de empréstimos

            c.execute("""

                INSERT INTO emprestimos (pedido_id, equipamento, encarregado_id, usuario_id, data_inicio, status)

                VALUES (?, ?, ?, ?, ?, ?)

            """, (

                pedido["id"],

                pedido["equipamento"],

                pedido["encarregado_id"],

                pedido["usuario_id"],

                datetime.now().strftime("%Y-%m-%d %H:%M:%S"),

                "ativo"

            ))

        elif acao == "reprovar":  # usando to usando 'reprovar' para diferenciar do admin

            novo_status = "recusado"

            flash_msg = "Pedido reprovado pelo encarregado."

        else:

            flash("Ação inválida.", "error")

            return redirect(url_for("painel_encarregado"))

        # atualiza o status do pedido e registra a data de decisão

        c.execute("""

            UPDATE pedidos

            SET status = ?, data_decisao = ?

            WHERE id = ? AND encarregado_id = ?

        """, (

            novo_status,

            datetime.now().strftime("%Y-%m-%d %H:%M:%S"),

            id,

            enc_id

        ))

        conn.commit()

    flash(flash_msg)

    return redirect(url_for("painel_encarregado"))

@app.route("/emprestimos_ativos")

@somente_encarregado_ou_admin_enc

def emprestimos_ativos():

    """

    Mostra apenas os empréstimos ativos do encarregado logado (ou admin atuando como encarregado)

    """

    enc_id = session.get("encarregado_id")

    if not enc_id:

        flash("Selecione um encarregado para gerenciar os empréstimos.", "warning")

        return redirect(url_for("selecionar_encarregado"))

    with conectar() as conn:

        c = conn.cursor()

        # busca apenas os empréstimos do encarregado logado

        c.execute("""

            SELECT e.id, e.equipamento, e.data_inicio, u.nome AS nome_aluno

            FROM emprestimos e

            JOIN usuarios u ON u.id = e.usuario_id

            WHERE e.encarregado_id = ? AND e.status='ativo'

            ORDER BY e.data_inicio DESC

        """, (enc_id,))

        emprestimos = c.fetchall()

    return render_template("emprestimos.html", emprestimos=emprestimos)

@app.route("/emprestimo_encarregado/<int:id>/finalizar")

@somente_encarregado_ou_admin_enc

def finalizar_emprestimo_encarregado(id):

    enc_id = session.get("encarregado_id")

    if not enc_id:

        return redirect(url_for("selecionar_encarregado"))

    with conectar() as conn:

        c = conn.cursor()

        # aatualiza apenas se o empréstimo pertence ao encarregado

        c.execute("""

            UPDATE emprestimos

            SET status='finalizado', data_fim=?

            WHERE id=? AND encarregado_id=? AND status='ativo'

        """, (datetime.now().strftime("%Y-%m-%d %H:%M:%S"), id, enc_id))

        # atualiza também o pedido associado, se tiver

        c.execute("""

            UPDATE pedidos

            SET status='finalizado', data_devolucao=?

            WHERE id=(SELECT pedido_id FROM emprestimos WHERE id=?) 

              AND status='emprestado'

        """, (datetime.now().strftime("%Y-%m-%d %H:%M:%S"), id))

        conn.commit()

    flash("Empréstimo finalizado com sucesso.")

    return redirect(url_for("emprestimos_ativos"))

@app.route("/tutorial")

def tutorial():

    return render_template("tutorial.html")

# -------------------------

# ações do aluno (cancelar e excluir histórico)

# -------------------------

@app.route("/pedido/cancelar/<int:id>", methods=["POST"])

@somente_logado

def cancelar_pedido(id):

    user_id = session.get("usuario_id")

    perfil = session.get("perfil")

    with conectar() as conn:

        c = conn.cursor()

        # Busca o pedido para garantir que ele existe

        c.execute("SELECT usuario_id, status FROM pedidos WHERE id=?", (id,))

        pedido = c.fetchone()

        if not pedido:

            flash("Pedido não encontrado.")

            return redirect(url_for("dashboard"))

        # Proteção: Só o dono do pedido ou o admin podem cancelar

        if perfil != "admin" and pedido["usuario_id"] != user_id:

            flash("Você não tem permissão para cancelar este pedido.")

            return redirect(url_for("dashboard"))

        # Só deixa cancelar se ainda estiver pendente

        if pedido["status"] != "pendente_encarregado":

            flash("Este pedido já foi analisado e não pode mais ser cancelado por aqui.")

            return redirect(url_for("dashboard"))

        # atualiza o status para cancelado

        c.execute("UPDATE pedidos SET status='cancelado' WHERE id=?", (id,))

        conn.commit()

    flash("Pedido cancelado com sucesso!")

    return redirect(url_for("dashboard"))

@app.route("/pedido/excluir-historico/<int:id>", methods=["POST"])

@somente_logado

def excluir_historico(id):

    user_id = session.get("usuario_id")

    perfil = session.get("perfil")

    with conectar() as conn:

        c = conn.cursor()

        c.execute("SELECT usuario_id, status FROM pedidos WHERE id=?", (id,))

        pedido = c.fetchone()

        if not pedido:

            flash("Pedido não encontrado.")

            return redirect(url_for("dashboard"))

        # proteção: Só o dono do pedido ou o admin podem excluir

        if perfil != "admin" and pedido["usuario_id"] != user_id:

            flash("Você não tem permissão para excluir este histórico.")

            return redirect(url_for("dashboard"))

        # só deixa excluir se o pedido já estiver finalizado, recusado ou cancelado

        if pedido["status"] in ["pendente_encarregado", "emprestado", "ativo"]:

            flash("Você não pode excluir um pedido que ainda está em andamento.")

            return redirect(url_for("dashboard"))

        # deleta o pedido do banco de dados

        c.execute("DELETE FROM pedidos WHERE id=?", (id,))

        conn.commit()

    flash("Registro excluído do seu histórico!")

    return redirect(url_for("dashboard"))

# -------------------------

# execução

# -------------------------

if __name__ == "__main__":
    criar_tabelas()
    app.run(debug=False)
