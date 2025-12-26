from browser_history.browsers import Edge
import datetime,pandas as pd,time

def getbrowserhistory():
    edge=Edge()
    hist=edge.fetch_history()
    print("bh module is running...")
    time.sleep(3)
    df=pd.DataFrame(hist.histories,columns=['datetime','url','title'])
    return df

if __name__ == "__main__":
    getbrowserhistory()
