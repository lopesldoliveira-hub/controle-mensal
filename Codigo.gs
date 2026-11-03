// Servidor do Controle Mensal. Roda na conta expeddosul e guarda tudo no Drive dela.
// Cadastre aqui quem pode entrar. Use senhas com pelo menos 8 caracteres, diferentes das senhas do Google.
// Para adicionar alguém, copie uma linha. Depois de alterar, publique uma nova versão.
var USUARIOS = {
  'lucas': 'TROQUE_ESTA_SENHA'
};

var NOME_PASTA = 'Controle Financeiro';
var ARQ_PRINCIPAL = 'lancamentos.csv', ARQ_CELULAR = 'celular.csv', ARQ_LIDO = 'celular_lido.txt';
var FUSO = 'America/Sao_Paulo';
var COLUNAS = ['id','data','mes','tipo','grupo','categoria','descricao','valor','status','parcela','origem','criado_em','baixado_em','serie_id'];
var C = {}; COLUNAS.forEach(function (n, i) { C[n] = i; });
var CATEGORIAS = [
  [/\b(aluguel|condominio|iptu|prestacao da casa|financiamento)\b/, 'Moradia', 'Fixa'],
  [/\b(internet|telefone|celular|tv a cabo)\b/, 'Internet e telefone', 'Fixa'],
  [/\b(plano de saude|convenio)\b/, 'Saúde', 'Fixa'],
  [/\b(escola|faculdade|mensalidade|curso)\b/, 'Educação', 'Fixa'],
  [/\b(netflix|spotify|prime|disney|assinatura|academia)\b/, 'Assinaturas', 'Fixa'],
  [/\b(seguro)\b/, 'Seguros', 'Fixa'],
  [/\b(emprestimo|consorcio)\b/, 'Dívidas e parcelas', 'Fixa'],
  [/\b(luz|energia|celesc|agua|semasa|gas)\b/, 'Contas de casa', 'Variável'],
  [/\b(mercado|supermercado|feira|padaria|acougue)\b/, 'Alimentação', 'Variável'],
  [/\b(gasolina|combustivel|posto|etanol|uber|99|onibus|pedagio|estacionamento|oficina|ipva|pneu)\b/, 'Transporte', 'Variável'],
  [/\b(farmacia|remedio|medico|dentista|exame|consulta)\b/, 'Saúde', 'Variável'],
  [/\b(cartao|fatura)\b/, 'Cartão de crédito', 'Variável'],
  [/\b(restaurante|ifood|lanche|pizza|delivery|almoco|jantar)\b/, 'Alimentação fora', 'Eventual'],
  [/\b(cinema|viagem|hotel|bar|show|festa|lazer)\b/, 'Lazer', 'Eventual'],
  [/\b(presente|roupa|sapato|material escolar)\b/, 'Compras e presentes', 'Eventual']
];
var CATEGORIAS_RECEITA = [
  [/\b(salario|adiantamento|ferias|13|decimo)\b/, 'Salário'],
  [/\b(comissao|bonus)\b/, 'Comissões e bônus'],
  [/\b(freela|freelance|servico extra)\b/, 'Trabalhos extras'],
  [/\b(rendimento|dividendo|juros)\b/, 'Investimentos'],
  [/\b(restituicao|reembolso)\b/, 'Reembolsos']
];

var VALIDADE_LOGIN_DIAS = 90;

function doGet() {
  return ContentService.createTextOutput('Servidor do Controle Mensal ativo.').setMimeType(ContentService.MimeType.TEXT);
}

// Único ponto de entrada da página. Nenhuma operação com dados acontece sem login válido.
function doPost(e) {
  var saida;
  try {
    var c = JSON.parse(e.postData.contents);
    if (c.acao === 'entrar') {
      saida = { ok: true, usuario: normalizarUsuario_(c.usuario), token: entrar_(c.usuario, c.senha) };
    } else {
      var usuario = validarToken_(c.token);
      if (c.acao === 'dados') saida = { ok: true, dados: dados_(c.mes) };
      else if (c.acao === 'lancar') saida = { ok: true, dados: lancar_(c.lancamento, usuario) };
      else if (c.acao === 'baixar') saida = { ok: true, dados: baixar_(c.id, c.mes) };
      else if (c.acao === 'excluir') saida = { ok: true, dados: excluir_(c.id, c.mes, c.escopo) };
      else if (c.acao === 'buscar') saida = { ok: true, busca: buscar_(c.termo) };
      else if (c.acao === 'editar') saida = { ok: true, dados: editar_(c.edicao, c.mes) };
      else throw new Error('Operação desconhecida.');
    }
  } catch (err) {
    var codigo = /^LOGIN_/.test(err.message) ? err.message : '';
    saida = { ok: false, codigo: codigo, erro: codigo ? '' : err.message };
  }
  return ContentService.createTextOutput(JSON.stringify(saida)).setMimeType(ContentService.MimeType.JSON);
}

function normalizarUsuario_(u) { return String(u || '').trim().toLowerCase(); }

function senhaValida_(s) { return typeof s === 'string' && s.length >= 8 && s !== 'TROQUE_ESTA_SENHA'; }

function entrar_(usuarioBruto, senha) {
  var u = normalizarUsuario_(usuarioBruto), cache = CacheService.getScriptCache();
  var chave = 'erros_' + Utilities.base64EncodeWebSafe(u).slice(0, 80);
  var erros = parseInt(cache.get(chave) || '0', 10);
  if (erros >= 10) throw new Error('LOGIN_BLOQUEADO');
  var cadastrada = Object.prototype.hasOwnProperty.call(USUARIOS, u) ? USUARIOS[u] : null;
  if (cadastrada === 'TROQUE_ESTA_SENHA') throw new Error('LOGIN_SEM_SENHA');
  if (!senhaValida_(cadastrada) || String(senha) !== cadastrada) {
    cache.put(chave, String(erros + 1), 900);
    throw new Error('LOGIN_INCORRETO');
  }
  cache.remove(chave);
  var validade = Date.now() + VALIDADE_LOGIN_DIAS * 86400000;
  var corpo = Utilities.base64EncodeWebSafe(u) + '.' + validade;
  return corpo + '.' + assinar_(corpo, cadastrada);
}

// A chave inclui a senha: ao trocar a senha de alguém, os logins antigos dessa pessoa deixam de valer.
function assinar_(corpo, senha) {
  var p = PropertiesService.getScriptProperties(), segredo = p.getProperty('SEGREDO');
  if (!segredo) { segredo = Utilities.getUuid() + Utilities.getUuid(); p.setProperty('SEGREDO', segredo); }
  return Utilities.base64EncodeWebSafe(Utilities.computeHmacSha256Signature(corpo, segredo + '|' + senha));
}

function validarToken_(token) {
  var p = String(token || '').split('.');
  if (p.length !== 3) throw new Error('LOGIN_EXPIRADO');
  var u;
  try { u = Utilities.newBlob(Utilities.base64DecodeWebSafe(p[0])).getDataAsString(); }
  catch (e) { throw new Error('LOGIN_EXPIRADO'); }
  var senha = Object.prototype.hasOwnProperty.call(USUARIOS, u) ? USUARIOS[u] : null;
  if (!senhaValida_(senha) || !(+p[1] > Date.now()) || assinar_(p[0] + '.' + p[1], senha) !== p[2]) throw new Error('LOGIN_EXPIRADO');
  return u;
}

function pasta_() {
  var it = DriveApp.getRootFolder().getFoldersByName(NOME_PASTA);
  return it.hasNext() ? it.next() : DriveApp.getRootFolder().createFolder(NOME_PASTA);
}

// O computador substitui o arquivo ao gravar, então ele é sempre procurado pelo nome.
function arquivo_(pasta, nome) {
  var it = pasta.getFilesByName(nome), melhor = null;
  while (it.hasNext()) {
    var f = it.next();
    if (!f.isTrashed() && (!melhor || f.getLastUpdated() > melhor.getLastUpdated())) melhor = f;
  }
  return melhor;
}

function texto_(arq) {
  return arq ? arq.getBlob().getDataAsString('UTF-8').replace(/^﻿/, '') : '';
}

function csv_(txt) {
  return txt.trim() ? Utilities.parseCsv(txt, ';') : [];
}

function celulaCsv_(v) {
  v = String(v === undefined || v === null ? '' : v);
  return /[;"\r\n]/.test(v) ? '"' + v.replace(/"/g, '""') + '"' : v;
}

function hojeIso_() { return Utilities.formatDate(new Date(), FUSO, 'yyyy-MM-dd'); }
function agoraIso_() { return Utilities.formatDate(new Date(), FUSO, "yyyy-MM-dd'T'HH:mm:ss.SSSXXX"); }
function novoId_() { return 'L' + Utilities.getUuid().replace(/-/g, '').slice(0, 12); }
function normalizar_(t) { return String(t).normalize('NFD').replace(/[̀-ͯ]/g, '').toLowerCase(); }

function centavos_(bruto) {
  var t = String(bruto).replace(/[^\d.,]/g, '');
  if (!t) return NaN;
  var m = t.match(/[.,](\d{1,2})$/), inteiro = t, dec = '';
  if (m) { inteiro = t.slice(0, m.index); dec = m[1]; }
  inteiro = inteiro.replace(/[.,]/g, '') || '0';
  return parseInt(inteiro, 10) * 100 + parseInt((dec + '00').slice(0, 2), 10);
}

function moedaCsv_(c) {
  return Math.floor(c / 100) + ',' + ('0' + (c % 100)).slice(-2);
}

function isoData_(t) {
  t = String(t).trim();
  var m = t.match(/^(\d{1,2})\/(\d{1,2})\/(\d{4})$/);
  if (m) return m[3] + '-' + ('0' + m[2]).slice(-2) + '-' + ('0' + m[1]).slice(-2);
  return /^\d{4}-\d{2}-\d{2}$/.test(t) ? t : '';
}

function somarMeses_(iso, n, dia) {
  var a = +iso.slice(0, 4), m = +iso.slice(5, 7) - 1 + n;
  a += Math.floor(m / 12); m = ((m % 12) + 12) % 12;
  var ultimo = new Date(Date.UTC(a, m + 1, 0)).getUTCDate();
  return a + '-' + ('0' + (m + 1)).slice(-2) + '-' + ('0' + Math.min(dia, ultimo)).slice(-2);
}

function classificar_(descricao, tipo) {
  var n = normalizar_(descricao), i;
  if (tipo === 'Receita') {
    for (i = 0; i < CATEGORIAS_RECEITA.length; i++) if (CATEGORIAS_RECEITA[i][0].test(n)) return [CATEGORIAS_RECEITA[i][1], 'Receita'];
    return ['Outras receitas', 'Receita'];
  }
  for (i = 0; i < CATEGORIAS.length; i++) if (CATEGORIAS[i][0].test(n)) return [CATEGORIAS[i][1], CATEGORIAS[i][2]];
  return ['Outros', 'Eventual'];
}

// Junta o arquivo do computador com o que o celular lançou e o computador ainda não leu.
function estado_() {
  var pasta = pasta_();
  var linhas = csv_(texto_(arquivo_(pasta, ARQ_PRINCIPAL))).slice(1);
  var lidos = {};
  texto_(arquivo_(pasta, ARQ_LIDO)).split(/\s+/).forEach(function (x) { if (x) lidos[x] = true; });
  var eventos = csv_(texto_(arquivo_(pasta, ARQ_CELULAR))).filter(function (e) { return e[0] !== 'evento' && !lidos[e[0]]; });
  eventos.forEach(function (e) {
    var dados = e.slice(2), acao = e[1];
    if (acao === 'incluir') {
      if (!linhas.some(function (l) { return l[0] === dados[0]; })) linhas.push(dados);
    } else if (acao === 'baixar') {
      linhas.forEach(function (l) {
        if (l[0] === dados[0]) { l[C.status] = l[C.tipo] === 'Receita' ? 'Recebido' : 'Pago'; l[C.baixado_em] = dados[1] || ''; }
      });
    } else if (acao === 'excluir') {
      linhas = linhas.filter(function (l) { return l[0] !== dados[0]; });
    } else if (acao === 'editar') {
      linhas.forEach(function (l) {
        if (l[0] !== dados[0]) return;
        l[C.data] = dados[1]; l[C.mes] = dados[1].slice(0, 7); l[C.grupo] = dados[2]; l[C.categoria] = dados[3];
        l[C.descricao] = dados[4]; l[C.valor] = dados[5];
        if (dados[6]) { l[C.status] = dados[6]; l[C.baixado_em] = dados[7] || ''; }
      });
    }
  });
  return { pasta: pasta, linhas: linhas, eventos: eventos };
}

function registrar_(novos) {
  var trava = LockService.getUserLock();
  trava.waitLock(20000);
  try {
    var s = estado_();
    var todos = s.eventos.concat(novos);
    var corpo = ['evento;acao;dados'].concat(todos.map(function (e) { return e.map(celulaCsv_).join(';'); })).join('\r\n') + '\r\n';
    var arq = arquivo_(s.pasta, ARQ_CELULAR);
    if (arq) arq.setContent('﻿' + corpo);
    else s.pasta.createFile(ARQ_CELULAR, '﻿' + corpo, 'text/csv');
  } finally {
    trava.releaseLock();
  }
}

function somarDias_(iso, n) {
  var d = new Date(Date.UTC(+iso.slice(0, 4), +iso.slice(5, 7) - 1, +iso.slice(8, 10) + n));
  return d.toISOString().slice(0, 10);
}

function totaisMes_(itens, mes) {
  var t = { receitas: 0, despesas: 0 };
  itens.forEach(function (i) { if (i.mes === mes) t[i.tipo === 'Receita' ? 'receitas' : 'despesas'] += i.valor; });
  return t;
}

function itens_() {
  var itens = [];
  estado_().linhas.forEach(function (l) {
    var data = isoData_(l[C.data]), valor = centavos_(l[C.valor]);
    if (!data || isNaN(valor)) return;
    itens.push({ id: l[C.id], data: data, mes: data.slice(0, 7), tipo: l[C.tipo] || 'Despesa', categoria: l[C.categoria] || 'Outros',
      descricao: l[C.descricao], valor: valor, pendente: (l[C.status] || 'Pendente') === 'Pendente', status: l[C.status], parcela: l[C.parcela] || '', origem: l[C.origem] || '', serie: l[C.serie_id] || '' });
  });
  var qtd = {};
  itens.forEach(function (i) { if (i.serie) qtd[i.serie] = (qtd[i.serie] || 0) + 1; });
  itens.forEach(function (i) { i.qtdSerie = i.serie ? qtd[i.serie] : 1; });
  return itens;
}

function porData_(a, b) {
  return a.data < b.data ? -1 : a.data > b.data ? 1 : String(a.descricao).localeCompare(String(b.descricao));
}

// Procura em todos os meses, na descrição, categoria, valor e data, sem diferenciar acentos.
function buscar_(termo) {
  var t = normalizar_(termo).trim();
  if (t.length < 2) throw new Error('Digite pelo menos 2 letras ou números para pesquisar.');
  var partes = t.split(/\s+/);
  var achados = itens_().filter(function (i) {
    var texto = normalizar_(i.descricao + ' ' + i.categoria + ' ' + moedaCsv_(i.valor) + ' ' + i.data.slice(8, 10) + '/' + i.data.slice(5, 7) + '/' + i.data.slice(0, 4));
    return partes.every(function (p) { return texto.indexOf(p) >= 0; });
  }).sort(porData_);
  var despesas = 0, receitas = 0;
  achados.forEach(function (i) { if (i.tipo === 'Receita') receitas += i.valor; else despesas += i.valor; });
  return { termo: termo, total: achados.length, despesas: despesas, receitas: receitas, hoje: hojeIso_(), itens: achados.slice(0, 100) };
}

function dados_(mes) {
  var hoje = hojeIso_();
  if (!/^\d{4}-(0[1-9]|1[0-2])$/.test(mes || '')) mes = hoje.slice(0, 7);
  var itens = itens_();
  var r = { recebido: 0, a_receber: 0, pago: 0, a_pagar: 0 }, futuros = {}, categorias = {}, vencidas = 0, vencidasValor = 0;
  var limite = mes > hoje.slice(0, 7) ? mes : hoje.slice(0, 7);
  itens.forEach(function (i) {
    if (i.mes === mes) {
      if (i.tipo === 'Receita') r[i.pendente ? 'a_receber' : 'recebido'] += i.valor;
      else {
        r[i.pendente ? 'a_pagar' : 'pago'] += i.valor;
        categorias[i.categoria] = (categorias[i.categoria] || 0) + i.valor;
      }
    }
    if (i.tipo === 'Despesa' && i.mes > limite) futuros[i.mes] = (futuros[i.mes] || 0) + i.valor;
    if (i.tipo === 'Despesa' && i.pendente && i.data < hoje) { vencidas++; vencidasValor += i.valor; }
  });
  return {
    mes: mes, mesAtual: hoje.slice(0, 7), hoje: hoje, r: r,
    saldo: r.recebido - r.pago, previsto: r.recebido + r.a_receber - r.pago - r.a_pagar,
    vencidas: vencidas, vencidasValor: vencidasValor,
    vencimentos: itens.filter(function (i) { return i.tipo === 'Despesa' && i.pendente && i.data <= somarDias_(hoje, 30); })
      .sort(function (a, b) { return a.data < b.data ? -1 : a.data > b.data ? 1 : 0; }).slice(0, 6),
    anterior: totaisMes_(itens, somarMeses_(mes + '-01', -1, 1).slice(0, 7)),
    futuros: Object.keys(futuros).sort().map(function (m) { return { mes: m, valor: futuros[m] }; }),
    categorias: Object.keys(categorias).map(function (n) { return { nome: n, valor: categorias[n] }; }).sort(function (a, b) { return b.valor - a.valor; }),
    itens: itens.filter(function (i) { return i.mes === mes; }).sort(porData_)
  };
}

function lancar_(f, usuario) {
  f = f || {};
  var tipo = f.tipo === 'Receita' ? 'Receita' : 'Despesa';
  var descricao = String(f.descricao || '').replace(/[;\r\n]+/g, ' ').replace(/^[\s=+@-]+/, '').replace(/\s+/g, ' ').trim().slice(0, 120);
  var valor = centavos_(f.valor), data = isoData_(f.data);
  var repetir = f.repetir === 'parcelado' || f.repetir === 'mensal' ? f.repetir : 'nao';
  var n = repetir === 'mensal' ? 12 : repetir === 'parcelado' ? parseInt(f.parcelas, 10) : 1;
  if (!descricao) throw new Error('Escreva o que é o lançamento.');
  if (!(valor > 0)) throw new Error('Informe um valor maior que zero.');
  if (!data) throw new Error('Informe uma data válida.');
  if (!(n >= 1 && n <= 120)) throw new Error('Informe de 1 a 120 parcelas.');
  var cat = classificar_(descricao, tipo), agora = agoraIso_(), serie = novoId_(), dia = +data.slice(8, 10), eventos = [];
  var porParcela = f.valorModo === 'parcela';
  var base = repetir === 'parcelado' && !porParcela ? Math.floor(valor / n) : valor;
  var feito = tipo === 'Receita' ? 'Recebido' : 'Pago';
  for (var k = 0; k < n; k++) {
    var d = somarMeses_(data, k, dia);
    var v = repetir === 'parcelado' && !porParcela && k === 0 ? valor - base * (n - 1) : base;
    var status = k === 0 && f.situacao === 'feito' ? feito : 'Pendente';
    var parcela = repetir === 'mensal' ? 'Mensal' : repetir === 'parcelado' && n > 1 ? (k + 1) + '/' + n : '';
    var id = novoId_();
    eventos.push([novoId_(), 'incluir', id, d, d.slice(0, 7), tipo, cat[1], cat[0], descricao, moedaCsv_(v), status, parcela, 'app:' + usuario, agora, status === 'Pendente' ? '' : agora, serie]);
  }
  registrar_(eventos);
  return dados_(data.slice(0, 7));
}

function baixar_(id, mes) {
  registrar_([[novoId_(), 'baixar', String(id), agoraIso_()]]);
  return dados_(mes);
}

function excluir_(id, mes, escopo) {
  var alvos = [String(id)];
  if (escopo === 'todos') {
    var estado = estado_(), linha = acharLinha_(estado.linhas, id);
    if (linha[C.serie_id]) alvos = estado.linhas.filter(function (l) { return l[C.serie_id] === linha[C.serie_id]; }).map(function (l) { return l[0]; });
  }
  registrar_(alvos.map(function (a) { return [novoId_(), 'excluir', a]; }));
  return dados_(mes);
}

function acharLinha_(linhas, id) {
  var achada = linhas.filter(function (l) { return l[0] === String(id); })[0];
  if (!achada) throw new Error('Esse lançamento não existe mais. Atualize a tela.');
  return achada;
}

function mesesEntre_(de, ate) {
  return (+ate.slice(0, 4) - +de.slice(0, 4)) * 12 + (+ate.slice(5, 7) - +de.slice(5, 7));
}

// Em "todos", a data escolhida vale para a parcela aberta; as outras mantêm a distância em meses.
function editar_(f, mes) {
  f = f || {};
  var descricao = String(f.descricao || '').replace(/[;\r\n]+/g, ' ').replace(/^[\s=+@-]+/, '').replace(/\s+/g, ' ').trim().slice(0, 120);
  var valor = centavos_(f.valor), data = isoData_(f.data);
  if (!descricao) throw new Error('Escreva o que é o lançamento.');
  if (!(valor > 0)) throw new Error('Informe um valor maior que zero.');
  if (!data) throw new Error('Informe uma data válida.');
  var linhas = estado_().linhas, atual = acharLinha_(linhas, f.id);
  var cat = classificar_(descricao, atual[C.tipo] === 'Receita' ? 'Receita' : 'Despesa');
  var todos = f.escopo === 'todos' && atual[C.serie_id];
  var alvos = todos ? linhas.filter(function (l) { return l[C.serie_id] === atual[C.serie_id]; }) : [atual];
  var dia = +data.slice(8, 10), feito = atual[C.tipo] === 'Receita' ? 'Recebido' : 'Pago', agora = agoraIso_();
  var dataBase = isoData_(atual[C.data]);
  registrar_(alvos.map(function (l) {
    var original = isoData_(l[C.data]) || dataBase;
    var nova = l === atual ? data : somarMeses_(data, mesesEntre_(dataBase, original), dia);
    var status = '';
    if (l === atual && f.situacao === 'feito' && l[C.status] === 'Pendente') status = feito;
    if (l === atual && f.situacao === 'pendente' && l[C.status] !== 'Pendente') status = 'Pendente';
    return [novoId_(), 'editar', l[0], nova, cat[1], cat[0], descricao, moedaCsv_(valor), status, status && status !== 'Pendente' ? agora : ''];
  }));
  return dados_(mes);
}
