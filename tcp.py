import asyncio
from time import time
from grader.tcputils import FLAGS_ACK, FLAGS_FIN, FLAGS_SYN, MSS, fix_checksum, make_header
from tcputils import *

class Servidor:
    def __init__(self, rede, porta):
        self.rede = rede
        self.porta = porta
        self.conexoes = {}
        self.callback = None
        self.rede.registrar_recebedor(self._rdt_rcv)

    def registrar_monitor_de_conexoes_aceitas(self, callback):
        """
        Usado pela camada de aplicação para registrar uma função para ser chamada
        sempre que uma nova conexão for aceita
        """
        self.callback = callback

    def _rdt_rcv(self, src_addr, dst_addr, segment):
        # Interpreta o cabeçalho do segmento recebido
        src_port, dst_port, seq_no, ack_no, \
            flags, window_size, checksum, urg_ptr = read_header(segment)

        if dst_port != self.porta:
            # Ignora pacotes que não são direcionados à porta deste servidor
            return

        # Verifica a integridade do checksum, caso não seja ignorado pela rede
        if not self.rede.ignore_checksum and calc_checksum(segment, src_addr, dst_addr) != 0:
            print('descartando segmento com checksum incorreto')
            return

        payload = segment[4*(flags>>12):]
        id_conexao = (src_addr, src_port, dst_addr, dst_port)

        if (flags & FLAGS_SYN) == FLAGS_SYN:
            # A flag SYN estar setada significa que é um cliente tentando estabelecer uma conexão nova
            novo_ack = seq_no + 1
            conexao = self.conexoes[id_conexao] = Conexao(self, id_conexao, seq_no, novo_ack)
            self.conexoes[id_conexao] = conexao

            # Responde ao SYN com sequência e confirmação
            resposta_flags = FLAGS_SYN + FLAGS_ACK
            segmento_resposta = fix_checksum(make_header(dst_port, src_port, seq_no, novo_ack, resposta_flags),
                                              src_addr, dst_addr)
            self.rede.enviar(segmento_resposta, src_addr)

            if self.callback:
                self.callback(conexao)
        elif id_conexao in self.conexoes:
            # Passa para a conexão adequada se ela já estiver estabelecida
            self.conexoes[id_conexao]._rdt_rcv(seq_no, ack_no, flags, payload)
        else:
             print('%s:%d -> %s:%d (pacote associado a conexão desconhecida)' %
                  (src_addr, src_port, dst_addr, dst_port))


class Conexao:
    def __init__(self, servidor, id_conexao, seq_inicial, ack_inicial):
        self.servidor = servidor
        self.id_conexao = id_conexao
        self.callback = None
        
        # Inicialização dos controles de sequência e confirmação
        self.seq_no = seq_inicial
        self.ack_no = ack_inicial
        self.seq_client = ack_inicial
        self.ack_client = ack_inicial
        self.sent_data = {}   
        self.segments = {}  
        self.SampleRTT = 0
        self.DevRTT = 0
        self.EstimatedRTT = 0
        self.TimeoutInterval = 1
        self.SentTime = 0
        
        # Controle do congestionamento e envio
        self.cwnd = MSS
        self.rcv_cwnd = 0
        self.reenvio = False
        self.open = True
        self.timer = None  

    def _exemplo_timer(self):
        self.reenvio = True
        self.cwnd = ((self.cwnd / MSS) // 2) * MSS
        primeiro_seq = list(self.sent_data.keys())[0]
        self.enviar(self.sent_data[primeiro_seq])

    def _rdt_rcv(self, seq_no, ack_no, flags, carga):
        
        if len(self.sent_data):
            if not self.reenvio:
                tempo_amostra = time() - self.SentTime
                primeira_amostra = 0 == self.SampleRTT
                self.SampleRTT = tempo_amostra
                if primeira_amostra:
                    self.EstimatedRTT = tempo_amostra
                    self.DevRTT = tempo_amostra / 2
                else:
                    self.EstimatedRTT = 0.875 * self.EstimatedRTT + 0.125 * tempo_amostra
                    self.DevRTT = 0.75 * self.DevRTT + 0.25 * abs(tempo_amostra - self.EstimatedRTT)
                self.TimeoutInterval = self.EstimatedRTT + 4 * self.DevRTT

            # Verifica se o ACK recebido confirma dados pendentes
            if ack_no > list(self.sent_data.keys())[0]:
                chave = list(self.sent_data.keys())[0]
                while chave < ack_no:
                    self.rcv_cwnd += len(self.segments[chave])
                    del self.segments[chave]
                    del self.sent_data[chave]
                    if not self.sent_data:
                        break
                    chave = list(self.sent_data.keys())[0]

                # Gerencia o timer conforme a existência de pacotes pendentes
                if self.sent_data:
                    if self.timer is not None:
                        self.timer.cancel()
                    self.timer = asyncio.get_event_loop().call_later(self.TimeoutInterval, self._exemplo_timer)
                else:
                    self.timer.cancel()

                if self.rcv_cwnd >= self.cwnd or not self.sent_data:
                    self.cwnd += MSS
                    self.rcv_cwnd = 0
                    if self.sent_data:
                        if self.timer is not None:
                            self.timer.cancel()
                        self.timer = asyncio.get_event_loop().call_later(self.TimeoutInterval, self._exemplo_timer)
                        primeiro = list(self.sent_data.keys())[0]
                        self.enviar(self.sent_data[primeiro])

        self.reenvio = False

        # Se o segmento não estiver na ordem ou se não houver carga (exceto FIN) ou se a conexão estiver fechada, ignora
        if seq_no != self.ack_no or (not carga and (flags & FLAGS_FIN) != FLAGS_FIN) or not self.open:
            return

        # Atualiza os números de sequência e confirmação
        src, sport, dst, dport = self.id_conexao
        self.seq_no = self.ack_no
        self.ack_no += len(carga)
        if (flags & FLAGS_FIN) == FLAGS_FIN:
            self.ack_no += 1

        self.ack_client = self.ack_no
        self.callback(self, carga)

        # Envia resposta de confirmação
        resposta_flags = FLAGS_ACK
        segmento_resposta = fix_checksum(make_header(dport, sport, self.seq_no, self.ack_no, resposta_flags),
                                          src, dst)
        self.servidor.rede.enviar(segmento_resposta, src)

        if (flags & FLAGS_FIN) == FLAGS_FIN:
            self.fechar()
            return

    def registrar_recebedor(self, callback):
        """
        Usado pela camada de aplicação para registrar uma função para ser chamada
        sempre que dados forem corretamente recebidos
        """
        self.callback = callback

    def enviar(self, dados):
        """
        Usado pela camada de aplicação para enviar dados
        """
        if not self.open:
            return

        src, sport, dst, dport = self.id_conexao
        indice = 0

        if not self.sent_data:
            # Fragmenta os dados em segmentos de tamanho compatível com MSS
            while indice < len(dados):
                trecho = dados[indice: indice + MSS]
                self.sent_data[self.seq_client] = trecho
                flags = FLAGS_ACK
                segmento_envio = fix_checksum(make_header(dport, sport, self.seq_client, self.ack_no, flags) + trecho,
                                              src, dst)
                self.segments[self.seq_client] = segmento_envio
                self.seq_client += len(trecho)
                indice += MSS

        total_enviado = 0

        # Verifica se é necessário reenvio (timer de timeout expirado)
        if not self.reenvio:
            for chave in self.sent_data:
                if total_enviado >= self.cwnd:
                    break
                self.servidor.rede.enviar(self.segments[chave], src)
                total_enviado += len(self.segments[chave])
        else:
            primeiro = list(self.sent_data.keys())[0]
            self.servidor.rede.enviar(self.segments[primeiro], src)
        
        # Atualiza o momento do envio para cálculo de RTT
        self.SentTime = time()

        if self.timer is not None:
            self.timer.cancel()
        self.timer = asyncio.get_event_loop().call_later(self.TimeoutInterval, self._exemplo_timer)
            
    def fechar(self):
        """
        Usado pela camada de aplicação para fechar a conexão
        """
        
        saddress, sport, daddress, dport = self.id_conexao
        self.callback(self, b'')
        segmento_fim = fix_checksum(make_header(dport, sport, self.seq_no, self.ack_no, FLAGS_FIN),
                                    saddress, daddress)
        self.servidor.rede.enviar(segmento_fim, saddress)
        self.open = False