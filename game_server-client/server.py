#jogo e funções do mesmo desenvolvidas pelo grupo
#Agradecimento ao Guilherme Henriques pela ajuda na conversão de jogo single-file para server/client

import random
import string
import socket
import sys
import time
import pickle
import crypt
import security
import json

class Server:
    
    def __init__(self):
        
        self.original_stack =   [(0,0),(0,1),(0,2),(0,3),(0,4),(0,5),(0,6),
                                (1,1),(1,2),(1,3),(1,4),(1,5),(1,6),
                                (2,2),(2,3),(2,4),(2,5),(2,6),
                                (3,3),(3,4), (3,5),(3,6),
                                (4,4),(4,5),(4,6),
                                (5,5),(5,6),
                                (6,6)]
        self.stack = []
        self.board =[]
        self.nplayers = 4
        self.players = []
        self.scores = {}
        self.conn = {}
        self.addr = {}
        self.client = {}
        self.hashed_public_key = {}
        self.nonce = {}
        self.sessionKey = {}
        self.consecutive_noplays = 0
        self.highest_double = None
        self.pseudoDeck = []
        self.sessKeys= []
        self.Ntiles = 40
      
        PUBLIC_KEY = security.rsaReadPublicKey('public.pem')
        PRIVATE_KEY = security.rsaReadPrivateKey('private.pem')

        if len(sys.argv) >= 2:
            if(int(sys.argv[1]) >=2 and int(sys.argv[1]) <= 4):
                self.nplayers = int(sys.argv[1])
        
        if len(sys.argv) >= 3:
            if(int(sys.argv[2]) >=0):
                self.Ntiles = int(sys.argv[2])
        
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.bind(('localhost', 8080))

        print("Waiting for players...\n")

        while True:
            s.listen(1)
            conn, addr = s.accept()
            
            #recieve auth0------------------------------------------------------
            cipherText = conn.recv(4096)
            plainText = security.rsaDecrypt(cipherText, PRIVATE_KEY)
            data = json.loads(plainText)

            if  not data['type'] == "AUTH0":
                raise Exception('Wrong message type "{}". Expected: "AUTH0".', data['type'])
            name = data['name']

            self.players += [name]
            self.conn[name]=conn
            self.addr[name]=addr            

            self.hashed_public_key[name] = data['hashed_public_key']
            self.nonce[name] = data['nonce']
            self.sessionKey[name] = data['session_key']
          
            #send auth1---------------------------------------------------
            signature = security.rsaSign(self.nonce[name],PRIVATE_KEY)
            message = dict()
            message['nonce'] = security.nonce()            
            message['type'] = 'AUTH1'
            message['sign'] = signature
            
            
            plainText = json.dumps(message).encode()
            cipherText = security.aesEncrypt(plainText, self.sessionKey[name])

            self.conn[name].sendall(cipherText)

            #recieve auth2-----------------------------------------------------
            cipherText = self.conn[name].recv(4096)
            print(self.conn[name])
            plainText = security.aesDecrypt(cipherText, self.sessionKey[name])
            message = json.loads(plainText)

            if not message['type'] == 'AUTH2':
                raise Exception('Wrong message type "{}". Expected: "AUTH2".', message['type'])
            
            signature = message['sign']
            publicKey = message['public_key']
            if not security.shaHash(publicKey) == self.hashed_public_key[name]:
               raise Exception('The hash received in "AUTH0" does not match the calculated hash.')
            
            self.hashed_public_key.pop(name)
            self.nonce.pop(name)
            
            print('The player',name,'athentication was sucessfull\n')

            if len(self.players) == self.nplayers:
                print("Lobby is full!\n")
                break

    def pseudoTile(self):
        
        for i,Ti in enumerate(self.original_stack):
            SESSION_KEY = security.aesKey()
            self.sessKeys.append(SESSION_KEY)
            Pi = security.aesEncrypt(json.dumps(Ti).encode(), SESSION_KEY)
            self.pseudoDeck.append((i,Pi))
            

    def unpseudoTile(self):
        indexKey = 0
        for Pi in self.pseudoDeck:
            jsonText = security.aesDecrypt(Pi, self.sessKeys[indexKey])
            Ti = json.loads(jsonText)
            print(Ti)
            indexKey +=1

    def sendShuf0(self, client):
        message = dict()
        message['type'] = 'SHUF0'
        message['stock'] = self.pseudoDeck

        plainText = json.dumps((0,message)).encode()
        cipherText = security.aesEncrypt(plainText,self.sessionKey[client])
        client.sendall(cipherText)
        print('Pseudonymized stock sent to',client)

    def recieveShuf1(self, client):
        cipherText = self.conn[client].recv(4096)
        plainText = (0, (security.aesDecrypt(cipherText, self.sessionKey[client])))
        message = json.loads(plainText)

        if not message['type'] == 'SHUF1':
            raise Exception('Wrong message type "{}". Expected: "SHUF1".', message['type'])
        
        global STOCK
        STOCK = message['stock']
        print('Shuffled and crypted Stock recieved from',client) 

       
    def play(self):
    
        end = 0
        print("Beggining of the game, the first player to reach 100 points win!\n")
        print("Scores:")
        for player in self.players:
            self.scores[player] = 0
            print("Player " + player + " -> " + str(self.scores[player]) + " points")
        
        msg = {'type': "start_series"}
        for player in self.players:
            self.conn[player].sendall(json.dumps((1,msg)).encode())
            time.sleep(0.02)

        input("\nPress a key to START")
        
        while(not end):
            print("------------------------------New Round----------------------------------")
            winner,points = self.play_game(self.nplayers, self.scores)
            print("Jogador " + winner + " wins the round with " + str(points) + " points!" )
            print("Scores:")
            msg = {'type': "new_game", 'scores': self.scores}
            for player in self.players:
                print("Player " + player + " -> " + str(self.scores[player]) + " points.")
                self.conn[player].sendall(json.dumps((1,msg)).encode())
                time.sleep(0.02)
            for player in self.players:
                if(self.scores[player] >= 100): #alterar para 100
                    print("----------------------------Game Ended----------------------------")
                    print("Player " + player + " won the series!!!")
                    msg={'type': "DISCONNECT", 'player': player, 'points': self.scores[player]}
                    for player in self.players:
                        self.conn[player].sendall(json.dumps((1,msg)).encode())
                        time.sleep(0.02)
                    end = 1
                    break
    
    def play_game(self, n_players, scores):
        assert n_players>=2 and n_players<=4

        msg={'type': "started_game"}
        for player in self.players:
            print("haha")
            self.conn[player].sendall((json.dumps((1,msg)).encode()))
            time.sleep(0.02)

        #flag for the end of the game
        game_end = 0
        
        #pseudonomization stage
        print("Pseudonomization Stage:\n")
        self.board = []
        self.stack = self.select_randomtiles()
        self.pseudoTile()
        #print(self.pseudoDeck)

        #Shuffling Stage
        print("Shuffling Stage Starting:\n")
        for player in self.players:
            self.sendShuf0(player)

        #first play in game, it is reseted if no doubles are drawn
        has_5pieces = 0
        
        while(not has_5pieces):
            
            #send 5 random tile to each player
            for i in range(5):
                for player in self.players:
                    self.send_random_tile(player)

            if(self.highest_double != None):
                self.board.append(self.highest_double[0])
                #next_players refres to the next player to play
                player_index = self.players.index(self.highest_double[1])
                if(player_index == self.nplayers - 1):
                    next_player = self.players[0]
                else:
                    next_player = self.players[player_index +1]
                print("The tile [" + str(self.highest_double[0][0]) + "|" + str(self.highest_double[0][1]) + "] from Player " + self.players[player_index] + " is the highest double tile, and so, the first to be played.\n")
                print("Board: ")
                self.print_board(self.board)
                print("\n")

                msg={'type': 'start_game', 'board': self.board, 'player_double': self.highest_double[1], 'next_player': next_player}
                for player in self.players:
                    self.conn[player].sendall(pickle.dumps(msg))
                time.sleep(0.02)

                has_5pieces=1
            else: 
                #When no double tiles are in players hands, the game resets 
                print("No double tiles in  ame, tiles return to stack to be shuffled again!")
                msg={'type': 'no_doubles'}
                for player in self.players:
                    self.conn[player].sendall(pickle.dumps(msg))
                time.sleep(0.2)
            
        #variable to check if there is no more tiles in the stack and the players cant play any more tiles
        self.consecutive_noplays = 0
        #variables to return
        points = 0
        winner = 0
        
        while(not game_end):
            #send info about game 

            print("--------------------Player " + next_player + " plays next!-----------------------------------")
            print("Board:")
            self.print_board(self.board)
            print("\n")
            
            #choose player next play
            msg={'type': 'play', 'board': self.board}
            self.conn[next_player].send(pickle.dumps(msg))
            time.sleep(0.2)
            
            try:
                data = self.conn[next_player].recv(4096)
                if data:
                    data = pickle.loads(data)
                    tile_toplay = data['tile_toplay']
                    numtiles_inhand = data['numtiles_inhand']
                    time.sleep(0.2)
            except socket.error as e:
                print(e)
            
            #draw tile if needed
            while(tile_toplay == None and len(self.stack) != 0):
                print("Sending new random tile from stack to player " + next_player + "\n")
                draw_tile = self.pick_random_tile()
                msg={'type': 'send_tile2', 'tile': draw_tile}
                self.conn[next_player].sendall(pickle.dumps(msg))
                time.sleep(0.2)

                #choose player next play
                msg={'type': 'play', 'board': self.board}
                self.conn[next_player].send(pickle.dumps(msg))
                time.sleep(0.2)
                
                try:
                    data = self.conn[next_player].recv(4096)
                    if data:
                        data = pickle.loads(data)
                        tile_toplay = data['tile_toplay']
                        numtiles_inhand = data['numtiles_inhand']
                        time.sleep(0.2)
                except socket.error as e:
                    print(e)
            
            #in case the stack is empty and so no new tile can be drawed
            if(tile_toplay==None):
                print("The stack is empty. The player shall pass!")
                self.consecutive_noplays += 1
                msg = {'type': "has_passed", 'player': next_player, 'board': self.board}
                for player in self.players:
                    self.conn[player].sendall(pickle.dumps(msg))
                    time.sleep(0.02)
            else:
                self.consecutive_noplays=0
                tile_play = tile_toplay[0]
                if(tile_toplay[1] == 'r'):
                    if(tile_toplay[0][0] != self.board[len(self.board)-1][1]):
                        tile_play = self.invert_tile(tile_play)
                    self.board.append(tile_play)
                else:
                    if(tile_toplay[0][1] != self.board[0][0]):
                        tile_play = self.invert_tile(tile_play)
                    self.board.insert(0,tile_play)
                msg = {'type': "has_played", 'player': next_player, 'board': self.board, 'tile': tile_toplay}
                for player in self.players:
                    if(player != next_player):
                        self.conn[player].sendall(pickle.dumps(msg))
                        time.sleep(0.02)
            
            if(numtiles_inhand==0):
                (winner,points) = self.calculate_points()
                self.scores[winner] += points
                game_end = 1
            if(self.consecutive_noplays==self.nplayers):
                print("Game ended. No more plays possible!")
                (winner,points) = self.calculate_points()
                self.scores[winner] += points
                game_end = 1
            if(self.players.index(next_player) == self.nplayers-1):
                next_player = self.players[0]
            else:
                next_player = self.players[self.players.index(next_player) + 1]
            print("Board after play: ")
            self.print_board(self.board)
        
        return (winner,points)
                
    
    #select random tiles
    def select_randomtiles(self):
        stack = []
        for i in range(self.Ntiles):
            j = random.randint(0,len(self.original_stack)-1)
            stack.append(self.original_stack[j])
        return stack

    #invert tile
    def invert_tile(self,tile):
        inverted_tile = (tile[1],tile[0])
        return inverted_tile
            
    
    #returns a copy of the stack
    def copy_stack(self,stack):
        new_stack = []
        for x in stack:
            new_stack.append(x)
        return new_stack
    
    def print_board(self,board):
        new_board = ""
        for i in board:
            new_board +=  "[" + str(i[0]) + "|" + str(i[1]) + "] "
        print(new_board)
    
    def send_random_tile(self, player):
        total_tiles = len(self.stack)
        j = random.randint(0,total_tiles-1)
        tile = self.stack[j]
        del(self.stack[j])
        msg={'type': 'send_tile', 'tile': tile}
        self.conn[player].sendall(pickle.dumps(msg))
        time.sleep(0.2)
        if(tile[0] == tile[1]):
            if self.highest_double == None:
                self.highest_double = tile,player
            else:
                if (tile[0] + tile[1] > self.highest_double[0][0] + self.highest_double[0][1]):
                    self.highest_double = tile,player

    def pick_random_tile(self):
        total_tiles = len(self.stack)
        assert total_tiles<=28
        j = random.randint(0,total_tiles-1)
        tile = self.stack[j]
        del(self.stack[j])
        return tile
    
    #return winner and the points he made
    def calculate_points(self):
        point_winner = 0
        points = []
        msg={'type': 'send_points'}
        for player in self.players:
            self.conn[player].sendall(pickle.dumps(msg))
            time.sleep(0.2)
            try:
                data = self.conn[player].recv(4096)
                if data:
                    data = pickle.loads(data)
                    points.append(data['points'])
                    time.sleep(0.2)
            except socket.error as e:
                print(e)
        
        #set to high value so it will be detected at least once
        min = 999999999
        for j in range(len(points)):
            if points[j] <= min:
                min = points[j]
                index_min = j 
        
        winner = self.players[index_min]
        
        for k in range(len(points)):
            if k == index_min:
                point_winner = point_winner - points[k]
            else:
                point_winner = point_winner + points[k]

        return (winner,point_winner)

server = Server()
server.play()
