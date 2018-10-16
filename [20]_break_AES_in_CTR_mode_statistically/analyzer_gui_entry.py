# -*- coding: utf-8 -*-
import tkinter as tk
from tkinter import ttk


# Entry : a tkinter.Entry override which is more practical to use
# There is a label to the left and a button to the right (optionnals) :
#
#	----------------------------------------------
#   |			|						|		 |
#   |	Label	|     Entry(redim)		| Button |
#   |			|						|		 |
#	----------------------------------------------
#   
#	The custom entry is resizable and every component too.
class AnalyserGUIEntry(ttk.Frame):

	# Constructor
	def __init__(self, master = None,  **kwargs ):

		# IP frame
		ttk.Frame.__init__(	self, master, **kwargs)

		self.entry  = None
		self.label  = None
		self.button = None

	# Place the elements if they are initialisation. 
	# Solve the initialisation order
	def pack(self, **kwargs):


		# Label Placement to the left
		if self.label != None:
			self.label.pack(	side = tk.LEFT,
								fill = tk.Y   )

		# Button Placement to the right
		if self.button != None:
			self.button.pack(	side = tk.RIGHT,
								fill = tk.Y	)
		
		# Entry Placement
		if self.entry != None:
			self.entry.pack( fill   = tk.BOTH,
							 expand =  tk.TRUE )

		# Frame Placement
		ttk.Frame.pack(	self, side = tk.TOP, fill   = tk.X	,
							  #expand = tk.X,
							  
							  **kwargs	 )

	# Add an Entry to the center 
	def add_entry(self, text_value, **kwargs):
		# Text Entry constructor
		self.text_value = tk.StringVar()
		self.entry = ttk.Entry(	self,
								textvariable = self.text_value ,
								justify = tk.RIGHT,
								style = 'FTMEntry.TEntry',
								**kwargs
								)
		self.set_value( text_value )


	# Add a label to the left of the entry
	def add_label(self, text,  **kwargs ):
		# Label Constructor 
		self.label_text = tk.StringVar()
		self.label = ttk.Label(	self,
								textvariable = self.label_text,
								anchor = tk.E ,
								justify = tk.RIGHT,
								style = 'FTMEntry.TLabel',
								**kwargs
								)
		self.set_label( text )


	# Add a [...] button to the right
	# the button's style can always be overrided with kwargs parameters
	def add_button(self, **kwargs):
		self.button = ttk.Button( self,
							  width = 4,
							  text = "...",
							  style = 'FTMEntry.TButton',
							  **kwargs
							)


	# Label getter/setter
	def get_label(self):
	    return self.label_text.get()

	# Label getter/setter
	def set_label(self, text):
		return self.label_text.set( text )

	# Entry getter/setter
	def get_value(self):
	    return self.text_value.get().rstrip("  ")
	# Entry getter/setter
	def set_value(self, text):
		# trailing whitespace for aesthetic purpose
		return self.text_value.set( text + "  " )
		
		
	 