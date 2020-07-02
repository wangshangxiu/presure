#include<iostream>
#include<string>
#include"CircleBuffer.hpp"
using namespace std;

int main()
{
        
    //---写指针在前，写指针右边剩余内存能写下数据
    cout << "写指针在前，写指针右边剩余内存能写下数据" << endl;
    {
        CircleBuffer<char> A(8);
        char In[5] = "city";
        cout << A.Write(In, 5) << endl;
        cout << A.GetReadPos() << endl;
        cout << A.GetWritePos() << endl;
        char Out[10] = {};
        if (A.Read(Out, 10))
        {
            cout << Out << endl;
        }
        cout << A.GetReadPos() << endl;
        cout << A.GetWritePos() << endl;
        cout << A.GetLength() << endl;
    }
    //---写指针在前，写指针右边剩余内存写不下数据，但是读指针左边内存够写下数据
    {
        cout << "写指针在前，写指针右边剩余内存写不下数据，但是读指针左边内存够写下数据" << endl;
        CircleBuffer<char> A(8);
        char In1[2] = { '1','2'  };
        char In2[2] = { '3','4'  };
        char In3[2] = { '5','6'  };
        A.Write(In1, 2) ;
        A.Write(In2, 2) ;
        A.Write(In3, 2) ;
        char Out[10] = {};
        if (A.Read(Out, 2))
        {
            cout << Out << endl;
        }
        cout << "ReadPos= " << A.GetReadPos() << endl;
        cout << "WritePos= " << A.GetWritePos() << endl;
        char In4[2] = { '7','8'  };
        A.Write(In4, 2);
        cout << "ReadPos= " << A.GetReadPos() << endl;
        cout << "WritePos= " << A.GetWritePos() << endl;

        if (A.Read(Out, 2))
        {
            //12345678
            cout << Out << endl;
        }
        cout << "ReadPos= " << A.GetReadPos() << endl;
        cout << "WritePos= " << A.GetWritePos() << endl;
        cout << A.GetLength() << endl;
        if(A.isEmpty()) cout << "Empty" << endl;
    }
    //---写指针在前，写指针右边剩余内存写不下数据，读指针左边内存也不够写下数据
    cout << "写指针在前，写指针右边剩余内存写不下数据，读指针左边内存也不够写下数据" << endl;
    CircleBuffer<char> A(9);
    char In1[2] = { '1','2'  };
    char In2[2] = { '3','4'  };
    char In3[2] = { '5','6'  };
    A.Write(In1, 2);
    A.Write(In2, 2);
    A.Write(In3, 2);
    char Out[10] = {};
    if (A.Read(Out, 2))
    {
        cout << Out << endl;
    }
    cout << "ReadPos= " << A.GetReadPos() << endl;
    cout << "WritePos= " << A.GetWritePos() << endl;
    char In4[4] = { '7','8','9' };
    A.Write(In4, 3);
    cout << "ReadPos= " << A.GetReadPos() << endl;
    cout << "WritePos= " << A.GetWritePos() << endl;
    char In5[2] = { 'a','b'  };//被扔掉了
    A.Write(In5, 2);
    cout << "ReadPos= " << A.GetReadPos() << endl;
    cout << "WritePos= " << A.GetWritePos() << endl;
    memset(Out,0,  sizeof(Out));
    if (A.Peak(Out, 3))
    {
        //12345678
        cout << "peak: "  <<  Out << endl;
    }
    memset(Out,0,  sizeof(Out));
    if (A.Read(Out, 3))
    {
        //12345678
        cout << Out << endl;
    }
    cout << A.GetLength() << endl;

    char In6[2] = { 'a','b'  };
    A.Write(In6, 2);
    cout << "ReadPos= " << A.GetReadPos() << endl;
    cout << "WritePos= " << A.GetWritePos() << endl;
    cout << A.GetLength() << endl;
    memset(Out,0,  sizeof(Out));
    if (A.Peak(Out, 4))
    {
        //12345678
        cout << "peak: "  <<  Out << endl;
    }
    memset(Out,0,  sizeof(Out));
    if (A.Read(Out, 4))
    {
        //12345678
        cout << Out << endl;
    }
    cout << A.GetLength() << endl;
    A.Write(In6, 2);
    cout << "ReadPos= " << A.GetReadPos() << endl;
    cout << "WritePos= " << A.GetWritePos() << endl;
    cout << A.GetLength() << endl;
    memset(Out,0,  sizeof(Out));
    if (A.Peak(Out, 3))
    {
        //12345678
        cout << "peak: "  <<  Out << endl;
    }
    memset(Out,0,  sizeof(Out));
    if (A.Read(Out, 3))
    {
        //12345678
        cout << Out << endl;
    }
    cout << "ReadPos= " << A.GetReadPos() << endl;
    cout << "WritePos= " << A.GetWritePos() << endl;
    cout << A.GetLength() << endl;

    A.Write(In6, 2);
    memset(Out,0,  sizeof(Out));
    if (A.Peak(Out, 10))
    {
        //12345678
        cout << "peak: "  <<  Out << endl;
    }
    memset(Out,0,  sizeof(Out));
    if (A.Read(Out, 10))
    {
        //12345678
        cout << Out << endl;
    }
    cout << "ReadPos= " << A.GetReadPos() << endl;
    cout << "WritePos= " << A.GetWritePos() << endl;
    cout << A.GetLength() << endl;
    //---读指针在前，读指针右边剩余内存能读出数据

    //---读指针在前，读指针右边剩余内存不能完整读出数据，但是加上写指针左边内存能完整读出数据

    //---读指针在前，读指针右边剩余内存不能完整读出数据，加上写指针左边内存也不能完整读出数据
    system("pause");
    return 0;
}








