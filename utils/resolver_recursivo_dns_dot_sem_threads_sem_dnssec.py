#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# -----------------------------------------------------------------------------
# Resolver DNS Recursivo Básico (TP1) — sem multithread, sem DNSSEC
# -----------------------------------------------------------------------------
# Este arquivo implementa um resolvedor DNS recursivo minimalista para atender
# aos pontos principais do Trabalho 1, porém propositalmente sem DNSSEC e sem
# multithread. Todo o código utiliza apenas chamadas de socket de baixo nível
# (UDP/TCP) e inclui fallback para TCP quando TC=1. Opcionalmente suporta DoT
# (DNS over TLS) somente para a consulta ao --ns, como stub->recursor.
#
# Características atendidas (sem DNSSEC / sem cache / sem threads):
#   - Resolução recursiva mesmo quando o servidor consultado é iterativo.
#   - Suporte a delegações (NS + glue A/AAAA), com busca dos IPs dos NS quando
#     necessário (consultando a própria hierarquia).
#   - Suporte a CNAME encadeado.
#   - Tratamento de respostas negativas (NXDOMAIN, NODATA) de forma simples.
#   - Fallback para TCP quando TC=1 (truncado) no cabeçalho DNS.
#   - EDNS(0) opcional para aumentar o payload em UDP (útil sem DNSSEC também).
#   - DNS over TLS (853) opcional para o servidor inicial --ns (com SNI).
#
# -----------------------------------------------------------------------------

import argparse   # importa argparse para processar parâmetros de linha de comando
import random     # importa random para gerar IDs de consulta DNS
import socket     # importa socket para operações de rede (UDP/TCP)
import ssl        # importa ssl para DNS over TLS (DoT) quando --mode=dot
import struct     # importa struct para empacotamento/desempacotamento binário
import time       # importa time para timeouts e métricas simples
from typing import List, Tuple, Optional, Dict, Any  # tipos para melhor legibilidade

# ------------------------------- Constantes DNS --------------------------------

QTYPE_MAP = {           # mapeia strings de tipos para seus códigos numéricos
    'A': 1,             # tipo A (IPv4)
    'NS': 2,            # tipo NS (servidor de nomes)
    'CNAME': 5,         # tipo CNAME (alias)
    'SOA': 6,           # tipo SOA (Start of Authority)
    'MX': 15,           # tipo MX (servidor de e-mail)
    'TXT': 16,          # tipo TXT (texto)
    'AAAA': 28,         # tipo AAAA (IPv6)
}
TYPE_TO_NAME = {v: k for k, v in QTYPE_MAP.items()}  # mapeia códigos numéricos para strings
CLASS_IN = 1           # classe IN (Internet)
TYPE_OPT = 41          # código de pseudo-RR OPT (EDNS(0))

# ----------------------- Funções de codificação/decodificação ------------------

def encode_name(name: str) -> bytes:
    """
    Converte um nome de domínio (ex.: 'www.ufms.br') em formato DNS wire (labels).
    Retorna bytes terminados por 0x00.
    """
    name = name.rstrip('.')                                  # remove ponto final, se houver
    if not name:                                             # se vazio, representa raiz
        return b'\x00'                                       # retorna byte zero
    parts = name.split('.')                                  # separa nos labels
    out = b''                                                # inicia acumulador de bytes
    for p in parts:                                          # percorre cada label
        lb = p.encode('utf-8')                               # codifica label para bytes
        if len(lb) > 63:                                     # valida tamanho do label
            raise ValueError('Label > 63 bytes: %r' % p)     # excedeu 63, erro
        out += bytes([len(lb)]) + lb                         # concatena tamanho + conteúdo
    return out + b'\x00'                                     # adiciona terminador 0x00


def decode_name(buf: bytes, offset: int) -> Tuple[str, int]:
    """
    Decodifica um nome no formato DNS (com possíveis ponteiros de compressão).
    Retorna a string do nome e o próximo offset após o campo (respeitando jumps).
    """
    labels = []                                              # lista de labels decodificados
    jumped = False                                           # indica se houve salto por ponteiro
    start = offset                                           # preserva offset inicial
    while True:                                              # laço até encontrar terminador
        if offset >= len(buf):                               # checa se passou do fim do buffer
            raise ValueError('decode_name: offset beyond buffer')  # erro de limite
        length = buf[offset]                                 # lê o primeiro byte (len ou ponteiro)
        if length & 0xC0 == 0xC0:                            # verifica bits de ponteiro (11xxxxxx)
            if offset + 1 >= len(buf):                      # garante que há dois bytes
                raise ValueError('decode_name: truncated pointer') # erro de truncamento
            ptr = ((length & 0x3F) << 8) | buf[offset + 1]   # extrai 14 bits do ponteiro
            if not jumped:                                   # se ainda não anotou o pós-nome
                start = offset + 2                           # guarda onde o chamador deve continuar
                jumped = True                                # marca que houve salto
            offset = ptr                                     # muda offset para o destino do ponteiro
            continue                                         # volta ao início do laço
        if length == 0:                                      # 0 indica fim do nome
            offset += 1                                      # avança uma posição
            break                                            # encerra laço
        offset += 1                                          # avança para os bytes do label
        label = buf[offset:offset+length]                    # fatia label
        labels.append(label.decode('utf-8', errors='replace')) # decodifica texto (tolerante)
        offset += length                                     # avança offset pelo comprimento do label
    return '.'.join(labels) if labels else '', (start if jumped else offset)  # monta nome e offset


def build_query(qname: str, qtype: int, rd: int, use_edns: bool, udp_payload_size: int = 1232) -> bytes:
    """
    Constrói um pacote DNS de consulta (query) com 1 pergunta (QDCOUNT=1).
    Pode incluir um registro OPT de EDNS(0) no Additional.
    """
    qid = random.randint(0, 0xFFFF)                          # gera ID aleatório de 16 bits
    flags = 0                                                # inicia flags em zero
    flags |= ((rd & 1) << 8)                                # seta RD (Recursion Desired) se solicitado
    header = struct.pack('!HHHHHH', qid, flags, 1, 0, 0, 0)  # empacota cabeçalho DNS (12 bytes)
    question = encode_name(qname) + struct.pack('!HH', qtype, CLASS_IN)  # QNAME+QTYPE+QCLASS

    if not use_edns:                                         # se não for usar EDNS(0)
        return header + question                             # retorna somente header+question

    opt_name = b'\x00'                                       # nome vazio (root) para OPT
    opt_udp_size = udp_payload_size                          # tamanho máximo de payload UDP negociado
    extended_rcode = 0                                       # extended RCODE (não usado aqui)
    edns_version = 0                                         # versão EDNS (0)
    z_flags = 0                                              # flags Z (não usadas)
    rdata = b''                                              # sem opções adicionais
    opt_rr = (                                              # monta pseudo-RR OPT
        opt_name +
        struct.pack('!H', TYPE_OPT) +
        struct.pack('!H', opt_udp_size) +
        struct.pack('!B', extended_rcode) +
        struct.pack('!B', edns_version) +
        struct.pack('!H', z_flags) +
        struct.pack('!H', len(rdata))
    )
    header = struct.pack('!HHHHHH', qid, flags, 1, 0, 0, 1)  # atualiza ARCOUNT=1 (tem OPT)
    return header + question + opt_rr                        # retorna consulta com OPT


def parse_header(buf: bytes) -> Dict[str, Any]:
    """
    Lê e interpreta o cabeçalho DNS (12 bytes), retornando campos relevantes.
    """
    if len(buf) < 12:                                        # verifica tamanho mínimo
        raise ValueError('DNS header muito curto')           # erro caso seja menor
    (qid, flags, qdcount, ancount, nscount, arcount) = struct.unpack('!HHHHHH', buf[:12])  # desempacota 12 bytes
    qr = (flags >> 15) & 1                                   # extrai bit QR (query/response)
    opcode = (flags >> 11) & 0xF                             # extrai opcode (4 bits)
    aa = (flags >> 10) & 1                                   # extrai AA (authoritative answer)
    tc = (flags >> 9) & 1                                    # extrai TC (truncated)
    rd = (flags >> 8) & 1                                    # extrai RD (recursion desired)
    ra = (flags >> 7) & 1                                    # extrai RA (recursion available)
    rcode = flags & 0xF                                      # extrai RCODE (4 bits)
    return {                                                 # retorna dicionário com campos
        'id': qid, 'qr': qr, 'opcode': opcode, 'aa': aa, 'tc': tc, 'rd': rd,
        'ra': ra, 'rcode': rcode, 'qdcount': qdcount, 'ancount': ancount,
        'nscount': nscount, 'arcount': arcount
    }


def parse_rr(buf: bytes, offset: int) -> Tuple[Dict[str, Any], int]:
    """
    Lê um RR (Resource Record) a partir do offset informado, retornando o RR parseado
    e o próximo offset após o registro.
    """
    name, offset = decode_name(buf, offset)                  # decodifica o NAME do RR
    if offset + 10 > len(buf):                               # garante tamanho do cabeçalho RR
        raise ValueError('RR header truncated')              # erro se não houver bytes suficientes
    rtype, rclass, ttl, rdlength = struct.unpack('!HHIH', buf[offset:offset+10])  # desempacota TYPE, CLASS, TTL, RDLENGTH
    offset += 10                                             # avança offset pelo cabeçalho RR
    rdata = buf[offset:offset+rdlength]                      # extrai RDATA bruto
    rdata_start = offset                                     # guarda início de RDATA para nomes comprimidos
    offset += rdlength                                       # avança offset pelo tamanho de RDATA

    parsed_rdata: Any                                        # declara variável tipada para RDATA decodificado
    if rtype == 1:                                           # se tipo A
        parsed_rdata = socket.inet_ntop(socket.AF_INET, rdata) if len(rdata) == 4 else rdata  # converte bytes -> string IPv4
    elif rtype == 28:                                        # se tipo AAAA
        parsed_rdata = socket.inet_ntop(socket.AF_INET6, rdata) if len(rdata) == 16 else rdata  # converte bytes -> string IPv6
    elif rtype in (2, 5, 15):                                # se NS, CNAME ou MX
        if rtype == 15 and len(rdata) >= 2:                  # trata MX com campo de preferência
            pref = struct.unpack('!H', rdata[:2])[0]         # desempacota preferência (16 bits)
            exchange, _ = decode_name(buf, rdata_start + 2)  # decodifica nome do servidor de e-mail
            parsed_rdata = {'preference': pref, 'exchange': exchange}  # monta dicionário
        else:                                                # caso NS ou CNAME (ou MX malformado)
            n, _ = decode_name(buf, rdata_start)             # decodifica nome simples
            parsed_rdata = n                                 # armazena string
    elif rtype == 16:                                        # se TXT
        txts = []                                            # lista de strings TXT
        i = 0                                                # índice de leitura
        while i < len(rdata):                                # percorre RDATA
            ln = rdata[i]                                    # lê tamanho do segmento TXT
            i += 1                                           # avança 1 byte do tamanho
            txts.append(rdata[i:i+ln].decode('utf-8', errors='replace'))  # extrai e decodifica trecho
            i += ln                                          # avança i pelo comprimento
        parsed_rdata = txts                                  # guarda lista de TXT
    elif rtype == 6:                                         # se SOA
        mname, p = decode_name(buf, rdata_start)             # decodifica MNAME
        rname, p = decode_name(buf, p)                       # decodifica RNAME
        parsed_rdata = {'mname': mname, 'rname': rname}      # monta dicionário mínimo
    elif rtype == TYPE_OPT:                                  # se OPT (EDNS)
        parsed_rdata = {'OPT': True}                         # marca presença de OPT
    else:                                                    # demais tipos não tratados
        parsed_rdata = rdata                                 # mantém bytes crus

    rr = {                                                   # monta dicionário do RR
        'name': name, 'type': rtype, 'class': rclass, 'ttl': ttl,
        'rdata_raw': rdata, 'rdata': parsed_rdata
    }
    return rr, offset                                        # retorna RR e o novo offset


def parse_message(buf: bytes) -> Dict[str, Any]:
    """
    Faz o parse completo de uma mensagem DNS em bytes, retornando dicionário
    com header, answers, authorities e additionals.
    """
    hdr = parse_header(buf)                                  # parse do cabeçalho
    offset = 12                                              # após cabeçalho DNS (12 bytes)
    for _ in range(hdr['qdcount']):                          # percorre seções de pergunta (geralmente 1)
        _, offset = decode_name(buf, offset)                 # ignora QNAME (apenas avança)
        if offset + 4 > len(buf):                            # garante espaço para QTYPE+QCLASS
            raise ValueError('Question truncated')           # erro se faltar bytes
        offset += 4                                          # avança 4 bytes de QTYPE+QCLASS
    answers = []                                             # lista de RRs da Answer
    authorities = []                                         # lista de RRs da Authority
    additionals = []                                         # lista de RRs do Additional
    for _ in range(hdr['ancount']):                          # itera pelos RRs da Answer
        rr, offset = parse_rr(buf, offset)                   # parse de um RR
        answers.append(rr)                                   # adiciona à lista de respostas
    for _ in range(hdr['nscount']):                          # itera pelos RRs da Authority
        rr, offset = parse_rr(buf, offset)                   # parse de um RR
        authorities.append(rr)                               # adiciona à lista de autoridade
    for _ in range(hdr['arcount']):                          # itera pelos RRs do Additional
        rr, offset = parse_rr(buf, offset)                   # parse de um RR
        additionals.append(rr)                               # adiciona à lista de adicionais
    return {'header': hdr, 'answers': answers, 'authorities': authorities, 'additionals': additionals}  # retorna estrutura


def _recvall(sock: socket.socket, n: int) -> bytes:
    """
    Lê exatamente 'n' bytes de um socket já conectado (TCP/DoT), bloqueando até
    receber tudo ou a conexão ser encerrada.
    """
    buf = b''                                                # inicia buffer vazio
    while len(buf) < n:                                      # enquanto não atingiu n bytes
        chunk = sock.recv(n - len(buf))                      # lê o restante necessário
        if not chunk:                                        # se veio vazio, conexão fechou
            break                                            # interrompe leitura
        buf += chunk                                         # acumula os bytes lidos
    return buf                                               # retorna o buffer acumulado


def send_udp(server: str, port: int, payload: bytes, timeout: float = 2.5) -> bytes:
    """
    Envia uma consulta DNS via UDP para (server, port) e aguarda a resposta.
    Usa getaddrinfo para suportar IPv4/IPv6. Fecha o socket explicitamente.
    """
    last_err = None                                          # armazena último erro observado
    infos = socket.getaddrinfo(server, port, 0, socket.SOCK_DGRAM)  # resolve endereços e famílias
    i = 0                                                    # índice para percorrer infos
    while i < len(infos):                                    # itera sobre tuplas de endereço
        family, socktype, proto, canonname, sockaddr = infos[i]  # desempacota tupla
        s = socket.socket(family, socktype, proto)           # cria socket UDP na família adequada
        s.settimeout(timeout)                                # define timeout de operação
        try:                                                 # tenta enviar/receber
            s.sendto(payload, sockaddr)                      # envia datagrama para sockaddr
            data, _ = s.recvfrom(65535)                      # recebe até 65535 bytes
            s.close()                                        # fecha socket (sem "with")
            return data                                      # retorna dados recebidos
        except Exception as e:                               # captura erro
            last_err = e                                     # guarda exceção
            try:
                s.close()                                    # garante fechamento do socket
            except Exception:
                pass
            i += 1                                           # tenta próximo sockaddr
            continue
    if last_err:                                             # se houve erro acumulado
        raise last_err                                       # propaga última exceção
    raise IOError('UDP: getaddrinfo não retornou endereços utilizáveis')  # erro genérico


def send_tcp(server: str, port: int, payload: bytes, timeout: float = 4.0) -> bytes:
    """
    Envia uma consulta DNS via TCP (com prefixo de 2 bytes de comprimento),
    aguardando a resposta completa e retornando o payload DNS (sem o prefixo).
    """
    last_err = None                                          # armazena último erro
    infos = socket.getaddrinfo(server, port, 0, socket.SOCK_STREAM)  # resolve endereços para TCP
    i = 0                                                    # índice de iteração
    while i < len(infos):                                    # percorre resoluções
        family, socktype, proto, canonname, sockaddr = infos[i]  # desempacota tupla
        s = socket.socket(family, socktype, proto)           # cria socket TCP
        s.settimeout(timeout)                                # define timeout
        try:                                                 # tenta conectar/enviar/receber
            s.connect(sockaddr)                              # conecta ao destino
            prefix = struct.pack('!H', len(payload))         # empacota comprimento de payload (2 bytes big-endian)
            s.sendall(prefix + payload)                      # envia tamanho + payload original
            hdr = _recvall(s, 2)                             # lê os 2 bytes de tamanho da resposta
            if not hdr:                                      # se não chegou, conexão encerrou
                raise IOError('TCP: conexão encerrada sem tamanho')  # erro
            (length,) = struct.unpack('!H', hdr)             # desempacota comprimento
            data = _recvall(s, length)                       # lê exatamente 'length' bytes
            s.close()                                        # fecha socket
            return data                                      # retorna resposta DNS crua
        except Exception as e:                               # em caso de erro
            last_err = e                                     # guarda erro
            try:
                s.close()                                    # garante fechamento
            except Exception:
                pass
            i += 1                                           # tenta próximo endereço
            continue
    if last_err:                                             # se houve erros
        raise last_err                                       # propaga último
    raise IOError('TCP: getaddrinfo não retornou endereços utilizáveis')  # erro genérico


def send_dot(server: str, payload: bytes, sni: Optional[str], timeout: float = 5.0, trace: bool = False) -> bytes:
    """
    Envia uma consulta DNS via DNS over TLS (porta 853) para o 'server'.
    Usa SNI se fornecido. O framing segue o mesmo de TCP (2 bytes de tamanho).
    """
    ctx = ssl.create_default_context()                       # cria contexto TLS com verificação padrão
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2             # impõe TLS 1.2 mínimo
    server_hostname = sni if sni else server                 # define SNI a partir do parâmetro ou do próprio server
    if trace:                                                # se estiver em modo trace
        print(f'[dot] connecting tls://{server}:853 SNI={server_hostname}')  # imprime destino e SNI
    last_err = None                                          # armazena último erro
    infos = socket.getaddrinfo(server, 853, 0, socket.SOCK_STREAM)  # resolve endereços para 853/TCP
    i = 0                                                    # índice de iteração
    while i < len(infos):                                    # percorre resoluções
        family, socktype, proto, canonname, sockaddr = infos[i]  # desempacota tupla
        raw = socket.socket(family, socktype, proto)         # cria socket TCP cru
        raw.settimeout(timeout)                              # define timeout
        try:                                                 # tenta conectar e negociar TLS
            raw.connect(sockaddr)                            # conecta TCP
            tls = ctx.wrap_socket(raw, server_hostname=server_hostname)  # envolve TLS com SNI
            tls.settimeout(timeout)                          # define timeout no socket TLS
            prefix = struct.pack('!H', len(payload))         # empacota tamanho do payload
            tls.sendall(prefix + payload)                    # envia tamanho + payload
            hdr = _recvall(tls, 2)                           # lê 2 bytes de tamanho da resposta
            if not hdr:                                      # se vazio, conexão encerrou
                try:
                    tls.close()                              # fecha TLS
                except Exception:
                    pass
                raise IOError('DoT: conexão encerrada sem tamanho')  # erro
            (length,) = struct.unpack('!H', hdr)             # desempacota comprimento
            data = _recvall(tls, length)                     # lê exatamente 'length' bytes
            try:
                tls.close()                                  # fecha TLS
            except Exception:
                pass
            try:
                raw.close()                                  # fecha TCP cru (já fechado pelo TLS, mas garantimos)
            except Exception:
                pass
            return data                                      # retorna resposta DNS
        except Exception as e:                               # em caso de erro
            last_err = e                                     # guarda erro
            try:
                raw.close()                                  # fecha TCP cru
            except Exception:
                pass
            i += 1                                           # tenta próximo sockaddr
            continue
    if last_err:                                             # se houve erros
        raise last_err                                       # propaga último
    raise IOError('DoT: getaddrinfo não retornou endereços utilizáveis')  # erro genérico


def _is_ip(addr: str) -> bool:
    """
    Retorna True se 'addr' for um literal IPv4 ou IPv6 válido; caso contrário, False.
    """
    try:
        socket.inet_pton(socket.AF_INET, addr)               # tenta interpretar como IPv4
        return True                                          # sucesso: é IPv4 literal
    except OSError:
        try:
            socket.inet_pton(socket.AF_INET6, addr)          # tenta interpretar como IPv6
            return True                                      # sucesso: é IPv6 literal
        except OSError:
            return False                                     # não é literal


def _deduce_sni(ns: str) -> Optional[str]:
    """
    Tenta deduzir o SNI a partir do endereço --ns. Se for hostname, usa ele.
    Se for IP conhecido (Google/Cloudflare/Quad9/AdGuard), retorna nome mapeado.
    """
    if not _is_ip(ns):                                       # se ns não é IP literal
        return ns                                            # usa o próprio hostname
    ip_map = {                                               # mapeamento de IPs públicos para hostnames de SNI
        "8.8.8.8": "dns.google",                             # Google Public DNS
        "8.8.4.4": "dns.google",
        "2001:4860:4860::8888": "dns.google",
        "2001:4860:4860::8844": "dns.google",
        "1.1.1.1": "cloudflare-dns.com",                     # Cloudflare
        "1.0.0.1": "cloudflare-dns.com",
        "2606:4700:4700::1111": "cloudflare-dns.com",
        "2606:4700:4700::1001": "cloudflare-dns.com",
        "9.9.9.9": "dns.quad9.net",                          # Quad9
        "149.112.112.112": "dns.quad9.net",
        "2620:fe::fe": "dns.quad9.net",
        "2620:fe::9": "dns.quad9.net",
        "94.140.14.14": "dns.adguard-dns.com",               # AdGuard
        "94.140.15.15": "dns.adguard-dns.com",
        "2a10:50c0::ad1:ff": "dns.adguard-dns.com",
        "2a10:50c0::ad2:ff": "dns.adguard-dns.com",
    }
    return ip_map.get(ns)                                    # retorna hostname conhecido ou None


def _bootstrap_resolve_host(host: str, timeout: float = 3.0) -> List[str]:
    """
    Resolve um hostname para IPs usando o resolver do SO; se falhar, consulta
    recursivamente recursores públicos em modo RD=1 (A e AAAA) para bootstrap.
    """
    if _is_ip(host):                                         # se já for IP literal
        return [host]                                        # retorna lista com o IP

    try:                                                     # tenta resolver via SO (getaddrinfo)
        addrs = []                                           # lista de IPs
        infos = socket.getaddrinfo(host, 53, 0, socket.SOCK_DGRAM)  # resolve para UDP
        j = 0                                                # índice
        while j < len(infos):                                # percorre resultados
            fam, st, pr, cn, sa = infos[j]                   # desempacota tupla
            ip = sa[0]                                       # extrai IP do sockaddr
            if ip not in addrs:                              # evita duplicados
                addrs.append(ip)                             # adiciona IP
            j += 1                                           # avança índice
        if len(addrs) > 0:                                   # se encontrou algo
            return addrs                                     # retorna lista
    except Exception:                                        # ignora quaisquer erros aqui
        pass

    recursors = ['8.8.8.8', '1.1.1.1', '9.9.9.9']            # recurssores públicos para bootstrap

    def _dns_query(ip: str, name: str, qtype_num: int) -> List[str]:
        """
        Função interna que envia consulta DNS para 'ip' pedindo 'name' do tipo 'qtype_num'
        com RD=1 e EDNS ativado. Retorna lista de strings (IPs) extraídas da Answer.
        """
        q = build_query(name, qtype_num, rd=1, use_edns=True)  # constrói consulta com RD=1 e EDNS
        try:                                                   # tenta via UDP
            resp = send_udp(ip, 53, q, timeout=timeout)        # envia UDP
            msg = parse_message(resp)                          # parse da resposta
            if msg['header'].get('tc') == 1:                   # se truncado (TC=1)
                resp = send_tcp(ip, 53, q, timeout=timeout)    # refaz via TCP
                msg = parse_message(resp)                      # parse da resposta TCP
            # filtra apenas RRs A/AAAA na Answer e devolve os rdata (strings IP)
            return [rr['rdata'] for rr in msg['answers'] if rr['type'] in (QTYPE_MAP['A'], QTYPE_MAP['AAAA'])]
        except Exception:
            return []                                          # erro no bootstrap: retorna lista vazia

    results: List[str] = []                                  # lista consolidada de IPs
    k = 0                                                   # índice do recursor
    while k < len(recursors):                               # percorre recurssores
        rec = recursors[k]                                  # seleciona recursor
        for qt in (QTYPE_MAP['A'], QTYPE_MAP['AAAA']):      # consulta A e AAAA
            ips = _dns_query(rec, host, qt)                 # envia consulta
            for ip in ips:                                  # para cada IP retornado
                if ip not in results:                       # evita duplicatas
                    results.append(ip)                      # adiciona IP
        if len(results) > 0:                                # se já obteve IPs
            break                                           # encerra laço de recurssores
        k += 1                                              # tenta próximo recursor
    return results if len(results) > 0 else []              # retorna resultados ou lista vazia


def _uniq_preserve(items: List[str]) -> List[str]:
    """
    Remove duplicados preservando a ordem original.
    """
    seen = set()                                             # conjunto de itens já vistos
    out = []                                                 # lista de saída sem duplicados
    for x in items:                                          # percorre itens de entrada
        if x not in seen:                                    # se ainda não visto
            seen.add(x)                                      # marca como visto
            out.append(x)                                    # adiciona ao resultado
    return out                                               # retorna lista sem duplicados


class MiniResolver:
    """
    Resolvedor recursivo minimalista, sem DNSSEC e sem cache/threads.
    Implementa: consulta direta RD=1 ao --ns (UDP/TCP/DoT) e, se necessário,
    resolução iterativa (RD=0) com referrals, NS+glue e CNAME chaining.
    """
    def __init__(self, ns: str, mode: str = 'dns', sni: Optional[str] = None, timeout: float = 3.0, trace: bool = False, use_edns: bool = True):
        """
        Construtor: recebe o servidor inicial (--ns), modo ('dns' ou 'dot'),
        SNI opcional, timeout, flag de trace e se usa EDNS no payload.
        """
        self.ns = ns                                         # armazena o argumento --ns (hostname/IP)
        self.mode = mode                                     # modo de transporte para --ns: 'dns' (UDP/TCP) ou 'dot'
        self.sni = sni                                       # SNI explícito (ou None para deduzir)
        self.timeout = timeout                               # timeout de operações de rede
        self.trace = trace                                   # habilita impressões de depuração
        self.use_edns = use_edns                             # define se inclui OPT (EDNS) nas queries
        self.ns_endpoints = _bootstrap_resolve_host(ns, timeout=self.timeout) or [ns]  # resolve/endpoints do --ns
        if self.trace:                                       # se trace ativo
            print(f'[bootstrap] NS endpoints: {", ".join(self.ns_endpoints)}')  # imprime IPs do --ns

    def _query(self, server_ip: str, payload: bytes, prefer_tcp: bool = False, prefer_dot_for_ns: bool = False) -> bytes:
        """
        Wrapper de transporte: escolhe UDP, TCP ou DoT conforme parâmetros.
        """
        if prefer_dot_for_ns and (self.mode == 'dot'):       # se for para usar DoT no --ns
            sni_val = self.sni if self.sni else _deduce_sni(self.ns)  # descobre SNI
            return send_dot(server_ip, payload, sni_val, timeout=self.timeout, trace=self.trace)  # envia via DoT
        if prefer_tcp:                                       # se preferir TCP
            return send_tcp(server_ip, 53, payload, timeout=self.timeout)  # envia via TCP/53
        return send_udp(server_ip, 53, payload, timeout=self.timeout)      # caso padrão: UDP/53

    def ask(self, server_ip: str, name: str, qtype: int, rd: int = 0, for_ns: bool = False) -> Dict[str, Any]:
        """
        Envia uma consulta DNS (RD conforme parâmetro) para 'server_ip' e faz o
        fallback para TCP se a resposta vier truncada (TC=1). Retorna dict parseado.
        """
        payload = build_query(name, qtype, rd, use_edns=self.use_edns)  # monta mensagem DNS
        resp = self._query(server_ip, payload, prefer_tcp=False, prefer_dot_for_ns=for_ns)  # envia (UDP ou DoT se ns)
        msg = parse_message(resp)                             # parse da resposta
        if msg['header']['tc'] == 1:                          # se truncado
            resp = self._query(server_ip, payload, prefer_tcp=True, prefer_dot_for_ns=False)  # refaz via TCP
            msg = parse_message(resp)                         # parse da resposta TCP
        return msg                                            # retorna mensagem

    def resolve(self, name: str, qtype_str: str = 'A') -> Dict[str, Any]:
        """
        Executa resolução "completa": tenta primeiro RD=1 direto no --ns (UDP/TCP/DoT);
        se encontrar apenas referrals, cai para resolução iterativa (RD=0) pelos authorities.
        """
        qtype = QTYPE_MAP.get(qtype_str.upper())              # converte QTYPE string para código
        if not qtype:                                         # se tipo não suportado
            raise ValueError('QTYPE não suportado: %r' % qtype_str)  # erro

        try:                                                  # tenta fluxo direto RD=1 no --ns
            q_current = name                                  # nome atual a consultar (pode mudar por CNAME)
            cname_chain = []                                  # acumula RRs CNAME para combinar na resposta
            used_addr = None                                  # registra qual endpoint respondeu
            hop_c = 0                                         # contador de saltos de CNAME
            while hop_c < 10:                                 # limita para evitar laços
                idx = 0                                       # índice para percorrer endpoints
                last_err = None                               # guarda último erro
                msg = None                                    # armazena resposta
                while idx < len(self.ns_endpoints):           # percorre os IPs do --ns
                    addr = self.ns_endpoints[idx]             # obtém um endpoint
                    if self.trace:                            # se trace
                        print(f'[direct] -> {addr} ? {q_current} {TYPE_TO_NAME.get(qtype,qtype)} (RD=1)')  # imprime tentativa
                    try:
                        msg = self.ask(addr, q_current, qtype, rd=1, for_ns=True)  # envia consulta RD=1
                        used_addr = addr                      # guarda endpoint usado
                        break                                 # sai do laço de endpoints
                    except Exception as e:                    # em caso de erro
                        last_err = e                          # guarda erro
                        if self.trace:                        # se trace
                            print(f'[direct] address failed: {addr} ({e})')  # imprime falha
                        idx += 1                              # tenta próximo endpoint
                        continue
                if msg is None:                               # se não conseguiu falar com nenhum endpoint
                    raise RuntimeError(f'No usable NS endpoint: last error: {last_err}')  # aborta

                rcode = msg['header']['rcode']                # lê RCODE da resposta
                if self.trace:                                # se trace
                    print(f'[direct] <- {used_addr} rcode={rcode} answers={len(msg["answers"])} authorities={len(msg["authorities"])}')  # imprime resumo

                if rcode != 0:                                # se não for NOERROR
                    if len(cname_chain) > 0:                  # se já acumulou CNAMEs
                        combined = dict(msg)                  # copia resposta
                        combined['answers'] = cname_chain + msg['answers']  # concatena cadeia de CNAME
                        return {'final': True, 'via': used_addr, 'message': combined}  # retorna
                    return {'final': True, 'via': used_addr, 'message': msg}  # retorna resposta tal qual

                # procura RR final do tipo solicitado para o q_current
                final_rr = [rr for rr in msg['answers'] if rr.get('type') == qtype and rr.get('name','').lower().rstrip('.') == q_current.lower().rstrip('.')]  # filtra RRs finais
                if len(final_rr) > 0:                         # se encontrou registros finais
                    combined = dict(msg)                      # copia resposta
                    combined['answers'] = cname_chain + msg['answers']  # inclui cadeia CNAME anterior
                    return {'final': True, 'via': used_addr, 'message': combined}  # retorna sucesso

                # verifica se há CNAME apontando para outro nome
                cnames = [rr for rr in msg['answers'] if rr.get('type') == QTYPE_MAP['CNAME'] and rr.get('name','').lower().rstrip('.') == q_current.lower().rstrip('.')]  # filtra CNAME
                if len(cnames) > 0:                           # se existe CNAME
                    cname_target = cnames[0].get('rdata')     # pega alvo do CNAME
                    cname_chain.extend(cnames)                # acumula na cadeia
                    if self.trace:                            # se trace
                        print(f'[direct-cname] {q_current} -> {cname_target}')  # informa redirecionamento
                    q_current = cname_target                  # atualiza nome corrente
                    hop_c += 1                                # incrementa contador de hop
                    continue                                  # reinicia ciclo RD=1 para o novo nome

                # se veio SOA na Authority, é resposta negativa NODATA ou similar (sem DNSSEC)
                has_soa = any(rr.get('type') == 6 for rr in msg['authorities'])  # checa presença de SOA
                if has_soa:                                   # se tem SOA
                    if len(cname_chain) > 0:                  # se houve CNAME antes
                        combined = dict(msg)                  # copia resposta
                        combined['answers'] = cname_chain + msg['answers']  # preserva cadeia
                        return {'final': True, 'via': used_addr, 'message': combined}  # retorna
                    return {'final': True, 'via': used_addr, 'message': msg}  # retorna resposta original

                # Referral: NOERROR com NS na Authority e sem Answer útil -> recursão iterativa
                has_ns_ref = any(rr.get('type') == QTYPE_MAP['NS'] for rr in msg['authorities']) and not msg['answers']  # checa padrão de referral
                if has_ns_ref:                                # se é referral
                    raise RuntimeError('Referral: non-recursive server; falling back to iterative')  # dispara fallback

                # Caso não caia em nenhum caso acima, retorna a resposta como está
                if len(cname_chain) > 0:                      # se tinha CNAME acumulado
                    combined = dict(msg)                      # copia resp
                    combined['answers'] = cname_chain + msg['answers']  # junta
                    return {'final': True, 'via': used_addr, 'message': combined}  # devolve
                return {'final': True, 'via': used_addr, 'message': msg}  # devolve resposta atual
            # se excedeu limite de hops de CNAME, cai no iterativo
            raise RuntimeError('Referral: exceeded hop limit; falling back to iterative')  # força fallback
        except Exception as e:                                 # erro no fluxo direto RD=1
            if self.trace:                                    # se trace
                print(f'[warn] NS direct failed: {e}')        # imprime aviso

        # Se chegou aqui, executa resolução iterativa clássica (RD=0) a partir dos endpoints
        return self._resolve_iterative(name, qtype, start_servers=list(self.ns_endpoints))  # chama método auxiliar

    def _resolve_iterative(self, name: str, qtype: int, start_servers: List[str]) -> Dict[str, Any]:
        """
        Implementa a resolução iterativa (RD=0). A cada passo:
          - envia query RD=0 a um authority;
          - se vier Answer final, retorna;
          - se vier referral (NS na Authority), tenta usar glue IP no Additional;
          - se não houver glue, resolve os nomes dos NS (A e AAAA) recursivamente;
          - repete até chegar ao autoritativo com a resposta, ou resposta negativa.
        """
        current_servers = list(start_servers)                 # fila de servidores a consultar
        visited = set()                                       # conjunto para evitar repetir (server,name,qtype)

        hop = 0                                               # contador de iterações
        while hop < 60:                                       # limite de segurança
            if len(current_servers) == 0:                     # se não há mais servidores
                raise RuntimeError('Sem servidores para continuar')  # aborta
            server_ip = current_servers.pop(0)                # retira o próximo servidor da fila
            key = (server_ip, name, qtype)                    # monta chave de visita
            if key in visited:                                # se já consultou esse par
                hop += 1                                      # incrementa hop
                continue                                      # tenta próximo
            visited.add(key)                                  # marca como visitado

            if self.trace:                                    # se trace ativo
                print(f'[iter] -> {server_ip} ? {name} {TYPE_TO_NAME.get(qtype,qtype)} (RD=0)')  # imprime tentativa

            try:
                msg = self.ask(server_ip, name, qtype, rd=0, for_ns=False)  # envia consulta RD=0
            except Exception as e:
                if self.trace:                                # em caso de erro
                    print(f'[iter] address failed: {server_ip} ({e})')  # imprime falha
                hop += 1                                      # incrementa hop
                continue                                      # tenta próximo servidor

            rcode = msg['header']['rcode']                    # lê RCODE
            if rcode != 0:                                    # se não for NOERROR
                if self.trace:
                    print(f'[iter] <- {server_ip} rcode={rcode}')  # imprime RCODE
                return {'final': True, 'via': server_ip, 'message': msg}  # retorna resposta de erro

            if len(msg['answers']) > 0:                       # se há respostas na Answer
                final = self._follow_cname_if_needed(msg, name, qtype, start_servers=start_servers)  # verifica CNAME
                if final is not None:                         # se obteve final (A/AAAA/MX/etc. ou cadeia resolvida)
                    if self.trace:
                        print(f'[iter] <- {server_ip} ANSWER')  # informa que obteve Answer
                    return {'final': True, 'via': server_ip, 'message': final}  # retorno final

            # Extrai nomes NS da Authority e possíveis glue IPs no Additional
            ns_names = [rr['rdata'] for rr in msg['authorities'] if rr['type'] == QTYPE_MAP['NS']]  # lista de hostnames de NS
            glue_ips = self._extract_glue_ips(msg['additionals'])  # lista de IPs (A/AAAA) já fornecidos
            next_ips: List[str] = []                        # próxima fila de IPs
            if len(glue_ips) > 0:                           # se há glue
                next_ips.extend(glue_ips)                   # usa-os diretamente

            # Se não houve glue, precisamos resolver os nomes dos NS (A e AAAA)
            if len(next_ips) == 0 and len(ns_names) > 0:    # sem glue mas há NS nomes
                j = 0                                       # índice sobre ns_names
                while j < len(ns_names):                    # percorre cada hostname de NS
                    ns_host = ns_names[j]                   # pega o hostname
                    ips = self._resolve_ns_host_ips_iterative(ns_host, start_servers=start_servers)  # resolve A/AAAA do NS
                    next_ips.extend(ips)                    # adiciona IPs encontrados
                    j += 1                                  # próximo NS

            uniq = _uniq_preserve(next_ips)                 # remove duplicados preservando ordem
            if len(uniq) == 0:                              # se não há próximos IPs
                if self.trace:                              # e trace ativo
                    print(f'[iter] <- {server_ip} (no next NS IPs)')  # informa que não há continuidade
                return {'final': True, 'via': server_ip, 'message': msg}  # retorna esta resposta (pode conter SOA/NODATA)

            # Empilha os próximos servidores encontrados no início da fila
            current_servers = uniq + current_servers         # prioriza novos IPs descobertos
            hop += 1                                         # incrementa contador e repete

        raise RuntimeError('Profundidade/iterações excedidas')  # se estourou limite


    def _follow_cname_if_needed(self, msg: Dict[str, Any], qname: str, qtype: int, start_servers: List[str]) -> Optional[Dict[str, Any]]:
        """
        Dada uma mensagem com Answer preenchida, verifica se há CNAME em vez de
        um RR final do tipo solicitado. Em caso de CNAME, resolve o alvo e
        retorna a mensagem final desse alvo; caso contrário, retorna a própria.
        """
        answers = msg['answers']                             # extrai a seção Answer
        cname_target = None                                   # armazena alvo de CNAME, se houver
        have_final = False                                    # indica se já veio o tipo final
        qname_l = qname.lower().rstrip('.')                   # normaliza nome da consulta
        idx = 0                                               # índice para percorrer answers
        while idx < len(answers):                             # itera por RRs da Answer
            rr = answers[idx]                                 # pega RR
            if rr['type'] == QTYPE_MAP['CNAME'] and rr['name'].lower().rstrip('.') == qname_l:  # CNAME do nome consultado
                cname_target = rr['rdata']                    # guarda o alvo
            if rr['type'] == qtype and rr['name'].lower().rstrip('.') == qname_l:               # RR final do tipo pedido
                have_final = True                             # marca que já tem resposta final
            idx += 1                                          # próximo RR
        if have_final:                                        # se já tem resposta final
            return msg                                        # retorna a própria mensagem
        if cname_target is not None:                          # se há CNAME
            if self.trace:                                    # se trace ativo
                print(f'[cname] {qname} -> {cname_target}')   # informa cadeia
            sub = self._resolve_iterative(cname_target, qtype, start_servers=start_servers)  # resolve alvo do CNAME
            return sub['message']                             # retorna mensagem do alvo
        return None                                           # se não havia CNAME nem final, retorna None


    def _extract_glue_ips(self, additionals: List[Dict[str, Any]]) -> List[str]:
        """
        Varre a seção Additional em busca de RRs A/AAAA (glue) e retorna lista
        de IPs (strings).
        """
        v4 = [rr['rdata'] for rr in additionals if rr['type'] == QTYPE_MAP['A']]     # extrai A
        v6 = [rr['rdata'] for rr in additionals if rr['type'] == QTYPE_MAP['AAAA']]  # extrai AAAA
        return v4 + v6                                       # concatena v4 e v6


    def _resolve_ns_host_ips_iterative(self, host: str, start_servers: List[str]) -> List[str]:
        """
        Resolve iterativamente (RD=0) os endereços A e AAAA de um hostname de NS,
        reutilizando a mesma cadeia de authorities indicada por 'start_servers'.
        """
        ips: List[str] = []                                   # lista de IPs encontrados
        for qt in (QTYPE_MAP['A'], QTYPE_MAP['AAAA']):        # consulta A e AAAA
            sub = self._resolve_iterative(host, qt, start_servers=start_servers)  # resolve
            ans = sub['message']['answers']                   # pega Answer da resposta
            k = 0                                             # índice para percorrer Answer
            while k < len(ans):                               # itera RRs
                rr = ans[k]                                   # RR atual
                if rr['type'] in (QTYPE_MAP['A'], QTYPE_MAP['AAAA']):  # se A/AAAA
                    ips.append(rr['rdata'])                   # adiciona o IP string
                k += 1                                        # próximo RR
        return _uniq_preserve(ips)                            # remove duplicados e retorna


"""
Processa argumentos, executa a resolução e imprime
o resultado em formato humano (Answers/Authorities/Additionals).
"""
p = argparse.ArgumentParser(description='Resolver DNS recursivo (sem DNSSEC/threads) com TCP fallback e DoT opcional no --ns.')  # cria parser
p.add_argument('--ns', required=True, help='Servidor inicial (hostname ou IP), ex.: a.root-servers.net ou 8.8.8.8')  # adiciona --ns
p.add_argument('--name', required=True, help='Nome de domínio a resolver, ex.: www.ufms.br')  # adiciona --name
p.add_argument('--qtype', default='A', choices=['A','AAAA','NS','MX','TXT','CNAME','SOA'], help='Tipo de consulta')  # adiciona --qtype
p.add_argument('--mode', default='dns', choices=['dns','dot'], help='dns: UDP+TCP; dot: DoT (853) para --ns apenas')  # adiciona --mode
p.add_argument('--sni', default=None, help='SNI para DoT (ex.: dns.google). Se omitido, tenta deduzir.')  # adiciona --sni
p.add_argument('--timeout', type=float, default=3.5, help='Timeout de socket (s)')  # adiciona --timeout
p.add_argument('--trace', action='store_true', help='Ativa rastreamento detalhado (passo a passo)')  # adiciona --trace
p.add_argument('--no-edns', action='store_true', help='Desabilita EDNS(0) na query (por padrão, EDNS é usado)')  # adiciona --no-edns

args = p.parse_args()                                     # parse dos argumentos

use_edns = not args.no_edns                               # determina se EDNS será usado
if args.mode == 'dot' and args.sni is None:               # se modo DoT e sem SNI
    args.sni = _deduce_sni(args.ns)                       # tenta deduzir automaticamente

r = MiniResolver(args.ns, mode=args.mode, sni=args.sni, timeout=args.timeout, trace=args.trace, use_edns=use_edns)  # instancia resolver

started = time.time()                                     # marca início para medir tempo
out = r.resolve(args.name, args.qtype)                    # executa resolução (completa)
elapsed = (time.time() - started) * 1000.0                # calcula duração em ms

msg = out['message']                                      # obtém mensagem final
hdr = msg['header']                                       # cabeçalho

print('--- Resultado ---')                                # cabeçalho de impressão
print(f"Via servidor: {out.get('via')}")                  # informa por qual servidor a resposta chegou
print(f"RCODE={hdr.get('rcode')} AA={hdr.get('aa')} RA={hdr.get('ra')} TC={hdr.get('tc')}")  # imprime flags básicas

# calcula TTL médio dos RRs em Answer, se houver
ttl_values = [rr.get('ttl', 0) for rr in msg['answers'] if isinstance(rr.get('ttl', None), int)]  # extrai TTLs numéricos
ttl_avg = (sum(ttl_values) / len(ttl_values)) if ttl_values else None                             # média simples

def fmt_rr(rr: Dict[str, Any]) -> str:
    """
    Formata um RR (dict) para texto legível (um por linha).
    """
    tname = TYPE_TO_NAME.get(rr['type'], str(rr['type']))  # converte tipo numérico para string
    rdata = rr['rdata']                                    # obtém rdata decodificado
    if isinstance(rdata, dict):                            # se é dicionário (ex.: MX)
        return f"{rr['name']}\t{rr['ttl']}\tIN\t{tname}\t{rdata}"  # formata dicionário
    if isinstance(rdata, list):                            # se é lista (ex.: TXT com múltiplas strings)
        return f"{rr['name']}\t{rr['ttl']}\tIN\t{tname}\t{'; '.join(rdata)}"  # junta lista em texto único
    return f"{rr['name']}\t{rr['ttl']}\tIN\t{tname}\t{rdata}"                # caso simples (str/bytes)

if len(msg['answers']) > 0:                                # se Answer não está vazia
    print('Answers:')                                      # imprime título
    i = 0                                                  # índice para percorrer answers
    while i < len(msg['answers']):                         # itera por answers
        print('  ', fmt_rr(msg['answers'][i]))             # formata e imprime cada RR
        i += 1                                             # próximo RR

if len(msg['authorities']) > 0:                            # se Authority não está vazia
    print('Authorities:')                                  # imprime título
    i = 0                                                  # índice para percorrer authorities
    while i < len(msg['authorities']):                     # itera por authorities
        print('  ', fmt_rr(msg['authorities'][i]))         # formata e imprime
        i += 1                                             # próximo RR

if len(msg['additionals']) > 0:                            # se Additional não está vazia
    print('Additionals:')                                  # imprime título
    i = 0                                                  # índice para percorrer additionals
    while i < len(msg['additionals']):                     # itera por additionals
        print('  ', fmt_rr(msg['additionals'][i]))         # formata e imprime
        i += 1                                             # próximo RR

# Classificação simples (sem DNSSEC): OK, NXDOMAIN, NODATA ou códigos de erro
classification = None                                      # inicia classificação
rcode = hdr.get('rcode')                                   # lê RCODE final
if rcode == 3:                                             # 3 => NXDOMAIN
    classification = 'NXDOMAIN'                            # classifica
elif rcode != 0:                                           # outros RCODEs não-zero
    rmap = {1: 'FORMERR', 2: 'SERVFAIL', 4: 'NOTIMP', 5: 'REFUSED'}  # mapa de alguns códigos
    classification = rmap.get(rcode, f'RCODE={rcode}')     # escolhe descrição
else:                                                      # NOERROR
    qtype_num = QTYPE_MAP.get(args.qtype.upper())          # converte qtype string
    has_qtype = any(rr.get('type') == qtype_num for rr in msg['answers'])  # verifica se Answer contém o tipo solicitado
    classification = 'OK' if has_qtype else 'NODATA'       # define OK/NODATA

print(f"Classification: {classification}")                 # imprime classificação
if ttl_avg is not None:                                    # se foi possível calcular média de TTL
    print(f"TTL avg (answers): {ttl_avg:.1f} s")           # imprime valor
print(f"Tempo total: {elapsed:.1f} ms")                    # imprime duração total


