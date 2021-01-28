import socket
import time
import sys
import random
import string
import pickle
import crypt

class Client:

    def __init__(self):
        
        self.hand=[]
        self.board=[]
        self.type = ''

        if len(sys.argv) >= 2:
            self.name = sys.argv[1]
        else:
            self.name = input("Pseudónimo: ")
        
        self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.s.connect(('localhost', 8080))
        msg = {"name": self.name}
        self.s.sendall(pickle.dumps(msg))
        print("You connected with name",self.name)

        running = 1
        while running:

            try:
                data = self.s.recv(4096)
                if data:
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
                        print("The player " + winner + " wins the game with " +  str(points) + " points!\n")
                        running = 0
            except socket.error as e:
                print(e)
            

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
        if(len(possible_plays)==0):
            print("No valid plays, player must draw from stack!\n")
            return None 
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

        
        
client = Client()