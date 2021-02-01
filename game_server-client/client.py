import socket
import time
import sys
import random
import string
import pickle
#import crypt
import security
import json
from C_Card import C_Card as c_card
from C_Card import PinError
existCard = None # see if can get authentication CC


class Client:

    def __init__(self):

        self.pseudohand = []
        self.STOCK = []
        self.hand=[]
        self.board=[]            
        self.shufMap = {}
        self.type = ''
        PUBLIC_KEY, PRIVATE_KEY = security.rsaKeyPair()
        SERVER_PUBLIC_KEY = security.rsaReadPublicKey('public.pem')
        self.SESSION_KEY = security.aesKey()
        self.message_size = 1048576

        # This is for testing
        self.cheatsOn = False
        self.cheat_stack =   [(0,0),(0,1),(0,2),(0,3),(0,4),(0,5),(0,6),
                                (1,1),(1,2),(1,3),(1,4),(1,5),(1,6),
                                (2,2),(2,3),(2,4),(2,5),(2,6),
                                (3,3),(3,4), (3,5),(3,6),
                                (4,4),(4,5),(4,6),
                                (5,5),(5,6),
                                (6,6)]

        #Authentication Stage Start--------------------------------------
        print("Authentication Stage\n")
        print("Will you use cc? \n")
        aux = input("y/n \n")
        if len(sys.argv) >= 2:
            self.name = sys.argv[1]
            self.cheatsOn = sys.argv[2] 
        else:
            self.name = input("Pseudónimo: ")
        
        self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.s.connect(('localhost', 8080))

        if(aux=="y"):
            existCard = c_card() #aqui
            try:
                print(existCard.login(0))
                existCard.login(0)
                msg = {"name": self.name,
                "type": "AUTH0", 
                "nonce": security.nonce(),
                'session_key': self.SESSION_KEY,
                "hashed_public_key": security.shaHash(security.rsaDumpKey(existCard.getPublicKey()))  }
                plainText = pickle.dumps(msg)
                cipherText = security.rsaEncrypt(plainText, SERVER_PUBLIC_KEY)
                self.s.sendall(cipherText)
                
                #recieve auth1----------------------------------------------------------
                cipherText = self.s.recv(self.message_size)
                plainText = security.aesDecrypt(cipherText,self.SESSION_KEY)
                message = pickle.loads(plainText)

                if not message['type'] == 'AUTH1':
                    raise Exception('Wrong message type "{}". Expected: "AUTH1".', message['type'])

                signature = message['sign']

                if not security.rsaVerify(msg['nonce'],signature,SERVER_PUBLIC_KEY):
                    raise Exception('Invalid signature of the nonce sent in "AUTH0".')

                #send auth2--------------------------------------------------------------
                signature = existCard.sign(0,message['nonce'])
                
                message['type'] = 'AUTH2'
                message['sign'] = signature
                message['public_key']= security.rsaDumpKey(existCard.getPublicKey())
            

                plainText = pickle.dumps(message)
                cipherText = security.aesEncrypt(plainText,self.SESSION_KEY)

                self.s.sendall(cipherText)

                print("Authentication sucessfull, you connected with pseudonym "+self.name)

                        
            except PinError as e:
                return None

        else:
       
            #send auth0-----------------------------------------------------
            msg = {"name": self.name,
                "type": "AUTH0", 
                "nonce": security.nonce(),
                'session_key': self.SESSION_KEY,
                "hashed_public_key": security.shaHash(security.rsaDumpKey(PUBLIC_KEY))  }

            plainText = pickle.dumps(msg)
            cipherText = security.rsaEncrypt(plainText, SERVER_PUBLIC_KEY)
            self.s.sendall(cipherText)
            
            #recieve auth1----------------------------------------------------------
            cipherText = self.s.recv(self.message_size)
            plainText = security.aesDecrypt(cipherText,self.SESSION_KEY)
            message = pickle.loads(plainText)

            if not message['type'] == 'AUTH1':
                raise Exception('Wrong message type "{}". Expected: "AUTH1".', message['type'])

            signature = message['sign']

            if not security.rsaVerify(msg['nonce'],signature,SERVER_PUBLIC_KEY):
                raise Exception('Invalid signature of the nonce sent in "AUTH0".')

            #send auth2--------------------------------------------------------------
            signature = security.rsaSign(message['nonce'], PRIVATE_KEY)

            message['type'] = 'AUTH2'
            message['sign'] = signature
            message['public_key']= security.rsaDumpKey(PUBLIC_KEY)
        

            plainText = pickle.dumps(message)
            cipherText = security.aesEncrypt(plainText,self.SESSION_KEY)

            self.s.sendall(cipherText)

            print("Authentication sucessfull, you connected with pseudonym " + self.name)

        running = 1
        while running:

            try:
                data = self.s.recv(self.message_size)
                if data:
                    try:
                        data = security.aesDecrypt(data, self.SESSION_KEY)
                        data = pickle.loads(data)
                    except:
                        data = pickle.loads(data)
                    
                    self.type = data['type']

                    if(self.type == 'start_game'):
                        self.board = data['board']
                        player_double = data['player_double']
                        next_player = data['next_player']
                        print("\n")
                        print("Player " + player_double + " had the highest double and so the tile was automatically played.\n")
                        print("Player " + next_player + " is the next to play.\n")
                        if(self.board[0] in self.hand):
                            self.hand.remove(self.board[0])
                        print("Board:")
                        self.print_board(self.board)
                        print("\n")
                        print("Your hand:")
                        self.print_board(self.hand)
                    elif(self.type == 'no_doubles'):
                        self.hand = []
                        print("\n")
                        print("No doubles were drawn! A new shuffle will be initiated!\n")
                    elif(self.type == 'start_series'):
                        print("\n")
                        print("Beggining of the series, the first player to reach 100 points win!\n")
                    elif(self.type == 'started_game'):
                        self.STOCK = []
                        print("\n")
                        print("Beggining of the game, best of luck for all!\n")
                    elif(self.type == 'new_game'):
                        scores = data['scores']
                        print("Scores:")
                        print(scores)
                        print("\n")
                    elif(self.type == 'send_tile'):
                        tile = data['tile']
                        self.hand.append(tile)
                        print("\n")
                        print("Tile received!\n")
                    elif(self.type == 'send_tile2'):
                        tile = data['tile']
                        self.hand.append(tile)
                        print("No tile to play, asking server to draw tile from stack:\n")
                        print("Tile received!\n")
                        print("Your Hand:")
                        self.print_board(self.hand)
                        print("Board:")
                        self.print_board(self.board)
                        print("\n")
                    elif(self.type == 'conf_5tiles'):
                        if(len(self.hand) == 5):
                            print("\n")
                            print("5 tiles in hand! Ready to start!\n") 
                    elif(self.type == 'play'):
                        print("Your turn: \n")
                        self.board = data['board']
                        print("Board:")
                        self.print_board(self.board)
                        print("\n")
                        print("Your Hand:")
                        self.print_board(self.hand)
                        print("\n")
                        tile_toplay = self.pick_possible_play()
                        msg = {"tile_toplay": tile_toplay, "numtiles_inhand" : len(self.hand)}
                        self.s.sendall(pickle.dumps(msg))
                        time.sleep(0.2)
                    elif(self.type == 'send_points'):
                        points = 0
                        for i in self.hand:
                            points = points + i[0]
                            points = points + i[1]
                        msg = {"points": points}
                        self.s.sendall(pickle.dumps(msg))
                        time.sleep(0.2)
                    elif(self.type == 'has_played'):
                        self.board = data['board']
                        player = data['player']
                        tile = data['tile']
                        print("The player " + player + " has played the tile [" + str(tile[0][0]) + "|" + str(tile[0][1]) + "]!\n")
                        print("Board:")
                        self.print_board(self.board)
                        print("\n")
                    elif(self.type == 'has_passed'):
                        self.board = data['board']
                        self.player = data['player']
                        print("The player " + player + " has passed!\n")
                    elif(self.type == 'DISCONNECT'):
                        winner = data['player']
                        points = data['points']

                        if(aux=="y"):
                            message = [player.c_card.infoCC.serial_number]
                            self.saveScore(message,points)

                        print("The player " + winner + " wins the game with " +  str(points) + " points!\n")
                        running = 0
                    elif(self.type == 'SHUF0'):
                        self.recieveShuf0(data['stock'])
                        self.sendShuf1()
                    elif(self.type == 'SEL0'):
                        self.recieveSel0(data['stock'])
                    elif(self.type == 'COMM0'):
                        self.send_comm1()
                    elif(self.type == 'COMM2'):
                        self.recieve_comm2(data['commits'])
                    elif(self.type == 'REVL0'):
                        self.recieveRevl0(data['stock'])
                    elif(self.type == 'REVL1'):
                        self.recieveRevl1(data['keys_dict'])
                    elif(self.type == 'DEAP0'):
                        self.recieveDeap0(data['array']) 
                    elif(self.type == 'REVL2'):
                        self.recieveRevl2(data['stock'])
                    elif(self.type == 'DEAS0'):
                        self.recieveDeas0(data['stack'])                            
                    elif(self.type == 'test'):
                        print(self.pseudohand)    

            except socket.error as e:
                print(e)
    
    def recieveDeas0(self,stack):
        for ptile in self.pseudohand:
            i = ptile[0]
            print(i)
            print(len(stack))
            pseudo_tile = ptile[1]
            private_key = ptile[2]
            
            tile_fromserver, key_fromserver = security.rsaDecrypt(stack[i],private_key)
            tile_here = security.aesDecrypt(pseudo_tile, key_fromserver)

            if(tile_fromserver == tile_here):
                print("The server sent this tile correctly!")

    def recieveDeap0(self, array):
        if random.randint(1,100) <= 70:
            public,private=security.rsaKeyPair()
            i = random.randint(0, len(self.pseudohand)-1)
            tuple_tile = self.pseudohand[i]
            array[tuple_tile[0]] = security.rsaDumpKey(public)
            tuple_tile = (tuple_tile[0], tuple_tile[1], private)
            self.pseudohand[i] = tuple_tile
            message = {'type': 'DEAP1', 'array': array}
            message = pickle.dumps(message)
            message = security.aesEncrypt(message, self.SESSION_KEY)
            self.s.sendall(message)
            print("Key array sent\n")
        else:
            message = {'type': 'NO_DEAP1'}
            message = pickle.dumps(message)
            message = security.aesEncrypt(message, self.SESSION_KEY)
            self.s.sendall(message)

            
    
    def recieveRevl2(self, stock):
        print(len(stock))
        for i,tile in enumerate(stock):
            print(i)
            key = self.shufMap[tile]
            uncipheredtile = security.aesDecrypt(tile,key)
            stock[i] = pickle.loads(uncipheredtile)
        message = {'type': "REVL4", 'stock': stock}
        plainText = pickle.dumps(message)
        self.s.sendall(plainText)
        time.sleep(0.1)
        print("Stock sent back\n")

    
    def recieveRevl1(self, keys_dict):
        print("Keys for decrypting received\n")
        for i, pseudotile in enumerate(self.pseudohand):
            #print(pseudotile)
            key = keys_dict[pseudotile]
            uncipheredtile = security.aesDecrypt(pseudotile,key)
            self.pseudohand[i] = pickle.loads(uncipheredtile)
        print("Hand decrypted")
    
    def recieveRevl0(self, stock):
            keys_dict = {}
            lista = self.shufMap.keys()  #tiles
            for x in lista:
                if x not in stock:
                    keys_dict[x] = self.shufMap[x]
            message = {'type': "REVL1", 'keys_dict': keys_dict}
            plainText = pickle.dumps(message)
            self.s.sendall(plainText)
            time.sleep(0.1)

    def recieveSel0(self, stock):
        self.STOCK = stock
        print("Stock recieved for selection from the Server")
        if random.randint(1,100) <= 70:
            tile = random.choice(self.STOCK)
            self.pseudohand.append(tile)
            self.STOCK.remove(tile)
            message = {'type': 'tile_accepted', 'stock': self.STOCK}
        else:
            message = {'type': 'tile_passed'}        
        plainText = pickle.dumps(message)
        cipherText = security.aesEncrypt(plainText, self.SESSION_KEY)
        self.s.sendall(cipherText)
        time.sleep(0.1)


    def recieveShuf0(self, stock):
        self.STOCK = stock
        print("Pseudonymized stock recieved from the Server")

    def sendShuf1(self):
        index = 0
        for Ti in self.STOCK:
            Ki = security.aesKey()
            if(len(self.shufMap) != 0):
                if Ki in self.shufMap.values():
                    Ki = security.aesKey()                     
            plainText = pickle.dumps(Ti)
            Ci = security.aesEncrypt(plainText,Ki)
            self.STOCK[index] = Ci
            self.shufMap[Ci] = Ki
            index += 1

        random.shuffle(self.STOCK)
        
        message = dict()
        message['type'] = 'SHUF1'
        message['stock'] = self.STOCK
        plainText = pickle.dumps(message)
        cipherText = security.aesEncrypt(plainText, self.SESSION_KEY)
        self.s.sendall(cipherText)
        print("Shuffled Stock sent to Server") 

    def send_comm1(self):
        global nonce1, nonce2
        nonce1 = security.nonce()
        nonce2 = security.nonce()

        global commit
        commit = security.shaHash(nonce1+nonce2+str(self.pseudohand))
        
        message = dict()
        message['type'] = 'COMM1'
        message['nonce1'] = nonce1
        message['commit'] = commit

        plainText = pickle.dumps(message)
        cipherText = security.aesEncrypt(plainText, self.SESSION_KEY)

        self.s.sendall(cipherText)
        print("Commitment to this hand sent")

    def recieve_comm2(self, commits):
        global COMMITS
        COMMITS = commits
        print("Recieved all the Bit Commitments and the Pseudonimized Stock from the server")

    
    #check player possible next plays and picks the play with more value, return None if no play is possible
    def pick_possible_play(self):
        possible_plays = []
        left = self.board[0][0]
        right = self.board[len(self.board)-1][1] 
        for x in self.hand:
            if(x[0] == left or x[1] == left):
                possible_plays.append((x,'l'))
            if(x[0] == right or x[1] == right):
                possible_plays.append((x,'r'))   
        if(len(possible_plays)==0) and (self.cheatsOn==False):
            print("No valid plays, player must draw from stack!\n")
            return None 

        # Gets best hand, without getting a random piece    
        elif (len(possible_plays)==0) and (self.cheatsOn==True): 
            for x in self.cheat_stack:
                if(x[0] == left or x[1] == left):
                    possible_plays.append((x,'l'))
                if(x[0] == right or x[1] == right):
                    possible_plays.append((x,'r'))
            print("I CHEATED")        
            max = 0
            cheats = 0
            for j in range(0,len(possible_plays)):
                value = possible_plays[j][0][0] + possible_plays[j][0][1]
                if(value>max):
                    max = value
                    cheats = j
            play_cheat = possible_plays[cheats]
            self.hand.remove(self.hand[0])
            print("Possible plays:")
            print(possible_plays)
            print("\n")
            print("Tile Played:")
            self.print_board([play_cheat[0]])
            if(play_cheat[1] == 'r'):
                print("Played on the right of the board!\n")
            else:
                print("Played on the left of the board!\n")
            return play_cheat  
        else:
            max = 0
            choosen_one = 0
            for j in range(0,len(possible_plays)):
                value = possible_plays[j][0][0] + possible_plays[j][0][1]
                if(value>max):
                    max = value
                    choosen_one = j
            play = possible_plays[choosen_one]
            self.hand.remove(play[0])
            print("Possible plays:")
            print(possible_plays)
            print("\n")
            print("Tile Played:")
            self.print_board([play[0]])
            if(play[1] == 'r'):
                print("Played on the right of the board!\n")
            else:
                print("Played on the left of the board!\n")         
        return play

    def print_board(self,board):
        new_board = ""
        for i in board:
            new_board +=  "[" + str(i[0]) + "|" + str(i[1]) + "] "
        print(new_board)

    def saveScore(self,message,points):
        #auxScore = (player)
        #plainText = pickle.dumps(player)  
        signature = c_card.sign(0,message)
        with open('score.txt', 'r') as r:
            lines = r.read().splitlines()
            if signature in r.read():
                prev_score = lines.split("=")
                score = points + prev_score
                with open('score.txt', 'w') as w:
                    w.write(lines.replace(prev_score,score))
                w.close()
            else:
                with open('score.txt', 'wb') as wb:
                    wb.write(signature+"="+points)    
                
        print("Score saved")           

        
        
client = Client()