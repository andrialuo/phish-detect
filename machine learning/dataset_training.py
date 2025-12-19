import numpy as np
import pandas as pd
import re


def loadEmailDataset(filepath):
    #columns: sender, subject, body, urls, label
    #df is dataframe

    df=pd.read_csv(filepath)
    required=["sender","subject","body","label"]
    for col in required:
        if col not in df.columns:
            print("column error")
    return df

def preprocess(df):
    #fill missing vals, make everything lowercase, remove whitespace and html tags
    df['sender']=df['sender'].fillna("")
    df['sender']=df['sender'].str.lower().str.strip()
    df['subject']=df['subject'].fillna("")
    df['subject']=df['subject'].str.lower().str.strip()
    df['body']=df['body'].fillna("")
    df['body']=df['body'].str.lower().str.strip()
    noHTML=[]
    for i in df['body']:
        clean=re.sub(r'<.*?>','',i)
        noHTML.append(clean)
    df['body']=noHTML
    return df

def extractSenderFeatures(df):
    #features: 1) length of email address 2) randomness of section before @

    lengths=[]
    randomScores=[]
    for sender in df['sender']:
        lengths.append(len(sender))
        local=sender.split('@')[0] if '@' in sender else sender
        digitCounter=sum(i.isdigit() for i in local)
        specialCharCounter=sum(not i.isalnum() for i in local)
        totalChars=max(len(local),1)
        #to calculate how random it is, we sum the number of digits and special characters and divide by total chars
        #suspicious emails are more likely to have a lot of numbers or special characters
        random=(digitCounter+specialCharCounter)/totalChars
        randomScores.append(random)
    featuresDF=pd.DataFrame({
        'length':lengths,
        'randomness':randomScores
    })
    return featuresDF

def extractSubjectFeatures(df):
    #features: 1) char length 2) avg word length 3) uppercase to lowercase ratio
    charLengths=[]
    avgWordLengths=[]
    upperToLowerRatio=[]
    for subject in df['subject']:
        charLengths.append(len(subject))
        words=subject.split()
        totalWordLen=sum(len(word)for word in words)
        avgWordLen=totalWordLen/max(len(words),1)
        avgWordLengths.append(avgWordLen)
        upperCounter=sum(i.isupper() for i in subject)
        lowerCounter=sum(i.islower() for i in subject)
        ratio=upperCounter/max(lowerCounter,1)
        upperToLowerRatio.append(ratio)

    featuresDF = pd.DataFrame({
        'char_length': charLengths,
        'avg_word_length': avgWordLengths,
        'upper_lower_ratio': upperToLowerRatio
    })

    return featuresDF


    
def extractBodyFeatures(df):
    #features: 1) avg sentence length 2) readability score using Flesch-Kincaid grade level 3)suspcicious word count
    avgSentenceLengths=[]
    readabilityScores=[]
    suspiciousCounter=[]
    suspiciousWords=['password','verify','login','urgent','click','account','bank','recover']
    for body in df['body']:
        sentences=[i.strip() for i in body.replace('!', '.').replace('?', '.').split('.') if i.strip()!='']
        totalWords=0
        for sentence in sentences:
            totalWords+=len(sentence.split())
        avgSentenceLength=totalWords/max(len(sentences),1)
        avgSentenceLengths.append(avgSentenceLength)
        words=body.split()
        totalSyllables=0
        for word in words:
            counter=0
            for i in word.lower():
                if i in 'aeiou':
                    counter+=1
            totalSyllables+=counter
        y=0.39*(len(words)/max(len(sentences),1))+11.8*(totalSyllables/max(len(words),1))-15.59
        readabilityScores.append(y)
        counter=0
        lower=body.lower()
        for word in suspiciousWords:
            counter+=lower.count(word)
        suspiciousCounter.append(counter)
        featuresDF = pd.DataFrame({
        'avg_sentence_length': avgSentenceLengths,
        'readability': readabilityScores,
        'suspicious_count': suspiciousCounter
    })
    return featuresDF


def extractURLFeatures(df):
    #features: 1) num of URLS 2) avg URL length 3)fraction of uncommon URLS
    numURLS=[]
    avgURLLengths=[]
    uncommonURLRatios=[]
    uncommonDomains=['.xyz', '.top', '.club', '.info', '.biz', '.online', '.site']
    url=r'https?://[^\s]+'
    for body in df['body']:
        urlList=re.findall(url,body)
        numURLS.append(len(urlList))
        length=0
        for url in urlList:
            length+=len(url)
        avgLength=length/max(len(urlList),1)
        avgURLLengths.append(avgLength)
        uncommonCounter=0
        for url in urlList:
            for domain in uncommonDomains:
                if url.lower().endswith(domain):
                    uncommonCounter+=1
                    break
        ratio=uncommonCounter/max(len(urlList),1)
        uncommonURLRatios.append(ratio)
    
    featuresDF = pd.DataFrame({
        'num_urls': numURLS,
        'avg_url_length': avgURLLengths,
        'fraction_uncommon': uncommonURLRatios
    })
    return featuresDF

def createFeatureMatrix(df):
    #combine all features into one matrix
    senderFeatures=extractSenderFeatures(df)
    subjectFeatures=extractSubjectFeatures(df)
    bodyFeatures=extractBodyFeatures(df)
    urlFeatures=extractURLFeatures(df)
    featuresDF=pd.concat([senderFeatures,subjectFeatures,bodyFeatures,urlFeatures],axis=1)
    return featuresDF

def normalize(X_train,X_test):
    #normalizing using mean and standard deviation from training data
    mean=X_train.mean(axis=0)
    std0=X_train.std(axis=0)
    std=np.where(std0==0,1,std0)
    X_train_normalized=(X_train-mean)/std
    X_test_normalized=(X_test-mean)/std
    return X_train_normalized, X_test_normalized

def binaryClassificationError(w,X,y):
    X_bias=np.hstack([np.ones((X.shape[0],1)),X])
    z=X_bias@w
    y1=np.sign(z)
    misclassified=np.sum(y1!=y)
    binaryError=misclassified/X.shape[0]
    return binaryError

def LogisticRegL2(X,labels,initialW,maxIterations,eta,reg,threshold):
    #gradient descent for logistic regression with L2 regularization
    # X: feature matrix, labels: (+/-1), initialW: initialWeights, eta: learning rate, reg: L2 regularization coefficient, threshold: when to stop
    X_bias=np.hstack([np.ones((X.shape[0],1)),X]) 
    w=initialW.copy() 
    i=0
    for i in range(1,maxIterations+1):
        z=X_bias@w
        num=labels[:,np.newaxis]*X_bias
        denom=1+np.exp(labels*z)
        grad=-np.mean(num/denom[:,np.newaxis],axis=0)
        grad+=reg*w
        w-=eta*grad
        if np.all(np.abs(grad)<threshold):
            break
    z=X_bias@w
    a=-labels*z
    lossper=np.log(1+np.exp(a))
    e_in=np.mean(lossper)
    return i,w,e_in

def splitDataset(df,y,testRatio=0.2):
    #randomly shuffle the dataset: .2 in test set, .8 in training
    shuffledI=np.random.permutation(len(df))
    testNum=int(len(df)*testRatio)
    testIndices=shuffledI[:testNum]
    trainIndices=shuffledI[testNum:]
    X_train=df.iloc[trainIndices].values
    X_test=df.iloc[testIndices].values
    y_train=y[trainIndices]
    y_test=y[testIndices]
    return X_train, X_test, y_train, y_test

def run():
    df=loadEmailDataset("xxx.csv") #change to actual file
    df=preprocess(df)
    X=createFeatureMatrix(df).values
    y=2*(df['label']==1)-1
    X_train,X_test,y_train,y_test=splitDataset(pd.DataFrame(X),y,testRatio=0.2)
    X_train_norm,X_test_norm=normalize(X_train,X_test)
    initialW=np.zeros(X_train_norm.shape[1]+1)
    maxIts=10000
    learningRate=0.01
    regLambda=0.01
    threshold=1e-6
    iters,w,e_in=LogisticRegL2(X_train_norm,y_train,initialW,maxIts,learningRate,regLambda,threshold)
    trainError=binaryClassificationError(w,X_train_norm,y_train)
    testError=binaryClassificationError(w,X_test_norm,y_test)
    print("Training E_in:", round(e_in, 4))
    print("Training binary error:", round(trainError, 4))
    print("Testing binary error:", round(testError, 4))

    #code will need to be added to test when you input something in it tells you if it's phishing or not. for now just getting the error correct


if __name__=="__main__":
    run()