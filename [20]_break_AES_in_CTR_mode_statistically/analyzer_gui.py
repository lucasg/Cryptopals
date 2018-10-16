# -*- coding: utf-8 -*-
from analyzer_gui_entry import AnalyserGUIEntry
import analyzer
# import xor
import os
import tkinter as tk
from tkinter import ttk, filedialog 





class AnalyserGUI(object):

	def __init__(self):
		self.ciphertexts = None

		self.root = tk.Tk()
		self.root.title( "Reused AES CTR keystream analyzer" )
		self.root.minsize(width = 600, height = 600)
		#self.root.maxsize(width = 1000, height = 1000)


		self.folder = AnalyserGUIEntry(self.root)
		self.folder.add_entry(os.path.join(os.getcwd(), "ctexts"))
		self.folder.add_label("ciphertext folder :")
		self.folder.add_button()
		self.folder.pack( padx   = 5, pady=5)

		self.ctext_frame = ttk.Frame(self.root, relief="sunken")
		self.ctext_frame_placeholder = ttk.Label(self.ctext_frame, text = "Ciphertext Analyzer", anchor = "center", justify = tk.CENTER)
		self.ctext_frame_placeholder.pack(padx   = 5, pady   = 5,expand = True, fill = tk.BOTH)
		self.ctext_frame.pack( padx   = 5, pady   = 5, expand = True, fill = tk.BOTH)

		self.buttons_frame = ttk.Frame(self.root, width=300, height=20)
		self.buttons_analyze = ttk.Button(self.buttons_frame, text="Analyze")
		self.buttons_save = ttk.Button(self.buttons_frame, text="Save")
		self.buttons_quit = ttk.Button(self.buttons_frame, text="Quit")
		self.buttons_quit.pack(side = tk.RIGHT, padx   = 1, pady   = 1)
		self.buttons_save.pack(side = tk.RIGHT, padx   = 1, pady   = 1)
		self.buttons_analyze.pack(side = tk.RIGHT, padx   = 1, pady   = 1)
		self.buttons_frame.pack(side = tk.BOTTOM,fill = tk.X, pady=5, padx   = 5)		

		self.folder.button.config(command = lambda : self.folder.set_value(filedialog.askdirectory()) )
		self.buttons_analyze.config( command = self.on_analyze )
		self.buttons_save.config( command = self.on_save, state='disabled') 
		self.buttons_quit.config( command = self.root.destroy )

		# launch the GUI
		self.root.mainloop()

	def on_save(self):
		'''
			Launch a pop-up to select the save filename and dump the 
			deciphered ciphertexts in it, along with the keystream
		'''
		if None == self.ciphertexts:
			return

		save_filepath = filedialog.asksaveasfilename() 
		with open(save_filepath, "w") as save_file:
			save_file.write('\n'.join( [ ''.join(analyzerself.hex_escape_array(line)) for line in self.ciphertexts]))

	def on_analyze(self):
		'''
			Load the ciphertexts (well any file really) located in the folder specified above
			and compute the most likely character to be the image of SPACE, as well as the 
			corresponding plaintexts.

			Create a grid of deciphered ciphertexts to operate upon in order to manually
			improve the recognition.
		'''
		self.ctext_frame.destroy()
		self.ctext_frame_placeholder.destroy()
		self.ctext_frame = ttk.Frame(self.root, relief="sunken")
		

		self.buttons_save.config( state='normal')

		# Load ciphertexts and compute keys
		self.ciphertexts, self.keys = analyzer.get_ciphertexts(self.folder.get_value())
		max_clen = max(map(len, self.ciphertexts))

		# Decode ciphertexts using most frequent key
		key = [ ord(k[0]) for k in self.keys]
		for i,s in enumerate(self.ciphertexts):
			self.ciphertexts[i] =  analyzer.xor( key , [ ord(c) for c in s] )
		

		# Canvas creation with double scrollbar
		ctext_frame_hscrollbar = ttk.Scrollbar(self.ctext_frame, orient = tk.HORIZONTAL)
		ctext_frame_vscrollbar = ttk.Scrollbar(self.ctext_frame, orient = tk.VERTICAL)
		ctext_frame_sizegrip = ttk.Sizegrip(self.ctext_frame)

		self.canvas = tk.Canvas(self.ctext_frame, bd=0, highlightthickness=0, yscrollcommand = ctext_frame_vscrollbar.set, xscrollcommand=ctext_frame_hscrollbar.set)
		ctext_frame_vscrollbar.config(command=self.canvas.yview)
		ctext_frame_hscrollbar.config(command=self.canvas.xview)

		
		
		# Matrix of ciphertexts
		self.ctext_subframe = ttk.Frame(self.canvas)
		self.keystream = []
		self.keystream_val = []
		for k in range(max_clen):
			col = []
			col_v = []
			ctext_col_frame = ttk.Frame(self.ctext_subframe)


			for c in range(len(self.ciphertexts)):
				cchar_val = tk.StringVar()

				valid_co = self.root.register(lambda operation, text_before, text_after, x = c, y = k: self.update_key( x, y, operation, text_before, text_after) )
				cchar = ttk.Entry(ctext_col_frame, textvariable=cchar_val, justify = tk.CENTER, validate='key', validatecommand = (valid_co, '%d','%S', '%P'))
				

				col.append(cchar)
				col_v.append(cchar_val)
				cchar.pack(side = tk.TOP, expand = tk.TRUE, fill = tk.X)
				
				if c < len(self.ciphertexts) and k < len(self.ciphertexts[c]):
					cchar_val.set(analyzer.hex_escape(self.ciphertexts[c][k]))
					cchar.config(width=1+len(cchar_val.get()))

				

			ctext_col_frame.pack(side=tk.LEFT)
			self.keystream.append(col)
			self.keystream_val.append(col_v)



		self.ctext_subframe.pack(padx   = 15, pady   = 15, fill = tk.BOTH, expand = tk.TRUE)
		ctext_frame_hscrollbar.pack(fill=tk.X, side=tk.BOTTOM, expand=tk.FALSE)
		ctext_frame_vscrollbar.pack(fill=tk.Y, side=tk.RIGHT, expand=tk.FALSE)
		ctext_frame_sizegrip.pack(in_ = ctext_frame_hscrollbar, side = tk.BOTTOM, anchor = "se")
		self.canvas.pack(side = tk.LEFT, padx  = 5, pady   = 5, fill = tk.BOTH, expand= tk.TRUE)
		self.ctext_frame.pack( padx   = 5, pady   = 5, expand = True, fill = tk.BOTH)

		
		self.canvas.create_window(0,0, window = self.ctext_subframe)
		self.root.update_idletasks()
		self.canvas.config(scrollregion = self.canvas.bbox("all"))
		self.canvas.xview_moveto(0) 
		self.canvas.yview_moveto(0)
					



	def update_key(self, x, y, operation, text_before, text_after):
		'''
			Callback called whenever the content of an entry change.
			Every character in the same column is then xor'd by the same integer shift.
		'''
		
		# Do not operate on deletion
		if not len(text_after) or not operation:
			return True

		# print("Callback cell {0:d}-{1:d} changed : {2:s} -> {3:s} !".format(x, y, analyzer.hex_escape(self.ctexts_cleaned[x][y]), text_after))

		shift = ord(self.ciphertexts[x][y]) ^ ord(text_after)
		for c,char in enumerate(self.keystream[y]):
			if y < len(self.ciphertexts[c]):

				if c != x:
					self.ciphertexts[c][y] = chr( ord(self.ciphertexts[c][y]) ^ shift)
					self.keystream_val[y][c].set( analyzer.hex_escape(self.ciphertexts[c][y]))
				else:
					self.ciphertexts[x][y] = text_after

			char.config( width = 1 + len(self.ciphertexts[x][y]) )

		self.root.update_idletasks()
		self.canvas.config(scrollregion = self.canvas.bbox("all"))
		return True





if __name__ == '__main__':

	

	gui = AnalyserGUI()