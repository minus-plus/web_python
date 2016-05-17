### python regex
#### diffent between match() and search()
re.match is anchored at the beginning of the string. That has nothing to do with newlines, so it is not the same as using ^ in the pattern.