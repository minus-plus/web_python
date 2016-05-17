import os

print os.path.dirname(__file__)
dir = os.path.join(os.path.dirname(__file__), 'templates')
print dir