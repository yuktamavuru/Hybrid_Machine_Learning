from django.db.models import Count
from django.db.models import Q
from django.shortcuts import render, redirect, get_object_or_404

import pandas as pd
from sklearn.feature_extraction.text import CountVectorizer
from sklearn.metrics import accuracy_score, confusion_matrix, classification_report
from sklearn.metrics import accuracy_score
from sklearn.tree import DecisionTreeClassifier
from sklearn.ensemble import VotingClassifier
# Create your views here.
from Remote_User.models import ClientRegister_Model,detect_botnet_attack,detection_ratio,detection_accuracy

def login(request):


    if request.method == "POST" and 'submit1' in request.POST:

        username = request.POST.get('username')
        password = request.POST.get('password')
        try:
            enter = ClientRegister_Model.objects.get(username=username,password=password)
            request.session["userid"] = enter.id

            return redirect('ViewYourProfile')
        except:
            pass

    return render(request,'RUser/login.html')

def index(request):
    return render(request, 'RUser/index.html')

def Add_DataSet_Details(request):

    return render(request, 'RUser/Add_DataSet_Details.html', {"excel_data": ''})


def Register1(request):

    if request.method == "POST":
        username = request.POST.get('username')
        email = request.POST.get('email')
        password = request.POST.get('password')
        phoneno = request.POST.get('phoneno')
        country = request.POST.get('country')
        state = request.POST.get('state')
        city = request.POST.get('city')
        address = request.POST.get('address')
        gender = request.POST.get('gender')
        ClientRegister_Model.objects.create(username=username, email=email, password=password, phoneno=phoneno,
                                            country=country, state=state, city=city,address=address,gender=gender)

        obj = "Registered Successfully"
        return render(request, 'RUser/Register1.html',{'object':obj})
    else:
        return render(request,'RUser/Register1.html')

def ViewYourProfile(request):
    userid = request.session['userid']
    obj = ClientRegister_Model.objects.get(id= userid)
    return render(request,'RUser/ViewYourProfile.html',{'object':obj})


def Botnet_Attack_Detection_Type(request):
    if request.method == "POST":

        if request.method == "POST":

            Fid= request.POST.get('Fid')
            SourcedFrom= request.POST.get('SourcedFrom')
            FileTimeUtc= request.POST.get('FileTimeUtc')
            SourceIp= request.POST.get('SourceIp')
            SourcePort= request.POST.get('SourcePort')
            SourceIpAsnNr= request.POST.get('SourceIpAsnNr')
            TargetIp= request.POST.get('TargetIp')
            TargetPort= request.POST.get('TargetPort')
            Payload= request.POST.get('Payload')
            SourceIpCountryCode= request.POST.get('SourceIpCountryCode')
            SourceIpRegion= request.POST.get('SourceIpRegion')
            SourceIpCity= request.POST.get('SourceIpCity')
            SourceIpLatitude= request.POST.get('SourceIpLatitude')
            SourceIpLongitude= request.POST.get('SourceIpLongitude')
            SourceIpMetroCode= request.POST.get('SourceIpMetroCode')
            SourceIpAreaCode= request.POST.get('SourceIpAreaCode')
            HttpRequest= request.POST.get('HttpRequest')

        df = pd.read_csv('IOT_Datasets.csv')

        def apply_response(Label):
            if (Label == "DDOS"):
                return 0  # DDOS
            elif (Label == "WORMS"):
                return 1  # WORMS
            elif (Label == "RECONNAISSANCE"):
                return 2  # RECONNAISSANCE

        df['results'] = df['Label'].apply(apply_response)

        X = df['Fid']
        y = df['results']

        print("Fid")
        print(X)
        print("Results")
        print(y)

        cv = CountVectorizer(lowercase=False, strip_accents='unicode', ngram_range=(1, 1))
        X = cv.fit_transform(X)

        models = []
        from sklearn.model_selection import train_test_split
        X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.20)
        X_train.shape, X_test.shape, y_train.shape

        print("Artificial Neural Network (ANN)")

        from sklearn.neural_network import MLPClassifier
        mlpc = MLPClassifier().fit(X_train, y_train)
        y_pred = mlpc.predict(X_test)
        print("ACCURACY")
        print(accuracy_score(y_test, y_pred) * 100)
        print("CLASSIFICATION REPORT")
        print(classification_report(y_test, y_pred))
        print("CONFUSION MATRIX")
        print(confusion_matrix(y_test, y_pred))
        models.append(('MLPClassifier', mlpc))
        detection_accuracy.objects.create(names="Artificial Neural Network (ANN)",
                                          ratio=accuracy_score(y_test, y_pred) * 100)

        print("SGD Classifier")

        from sklearn.linear_model import SGDClassifier
        sgd_clf = SGDClassifier(loss='hinge', penalty='l2', random_state=0)
        sgd_clf.fit(X_train, y_train)
        sgdpredict = sgd_clf.predict(X_test)
        print("ACCURACY")
        print(accuracy_score(y_test, sgdpredict) * 100)
        print("CLASSIFICATION REPORT")
        print(classification_report(y_test, sgdpredict))
        print("CONFUSION MATRIX")
        print(confusion_matrix(y_test, sgdpredict))


        print("Gradient Boosting Classifier")

        from sklearn.ensemble import GradientBoostingClassifier
        clf = GradientBoostingClassifier(n_estimators=100, learning_rate=1.0, max_depth=1, random_state=0).fit(
            X_train,
            y_train)
        clfpredict = clf.predict(X_test)
        print("ACCURACY")
        print(accuracy_score(y_test, clfpredict) * 100)
        print("CLASSIFICATION REPORT")
        print(classification_report(y_test, clfpredict))
        print("CONFUSION MATRIX")
        print(confusion_matrix(y_test, clfpredict))
        models.append(('GradientBoostingClassifier', clf))



        classifier = VotingClassifier(models)
        classifier.fit(X_train, y_train)
        y_pred = classifier.predict(X_test)

        Fid1 = [Fid]
        vector1 = cv.transform(Fid1).toarray()
        predict_text = classifier.predict(vector1)

        pred = str(predict_text).replace("[", "")
        pred1 = pred.replace("]", "")

        prediction = int(pred1)

        if (prediction == 0):
            val = 'DDOS'
        elif (prediction == 1):
            val = 'WORMS'
        elif (prediction == 2):
            val = 'RECONNAISSANCE'



        print(val)
        print(pred1)

        detect_botnet_attack.objects.create(
        Fid=Fid,
        SourcedFrom=SourcedFrom,
        FileTimeUtc=FileTimeUtc,
        SourceIp=SourceIp,
        SourcePort=SourcePort,
        SourceIpAsnNr=SourceIpAsnNr,
        TargetIp=TargetIp,
        TargetPort=TargetPort,
        Payload=Payload,
        SourceIpCountryCode=SourceIpCountryCode,
        SourceIpRegion=SourceIpRegion,
        SourceIpCity=SourceIpCity,
        SourceIpLatitude=SourceIpLatitude,
        SourceIpLongitude=SourceIpLongitude,
        SourceIpMetroCode=SourceIpMetroCode,
        SourceIpAreaCode=SourceIpAreaCode,
        HttpRequest=HttpRequest,
        Prediction=val)

        return render(request, 'RUser/Botnet_Attack_Detection_Type.html',{'objs': val})
    return render(request, 'RUser/Botnet_Attack_Detection_Type.html')



