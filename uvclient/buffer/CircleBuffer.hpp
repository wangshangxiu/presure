#ifndef _CIRCLE_BUFFER_HPP_
#define _CIRCLE_BUFFER_HPP_
#include<string.h>
#include<assert.h>
template<typename T>
class CircleBuffer
{
public:
    // 构造函数
    CircleBuffer(size_t size)
    {
        m_nBufSize = size;
        m_nReadPos = 0;
        m_nWritePos = 0;
        m_pBuf = new T[m_nBufSize];
        m_bEmpty = true;
        m_bFull = false;
    }

    //析构函数
    ~CircleBuffer()
    {
        if (m_pBuf)
        {
            delete[] m_pBuf;
            m_pBuf = nullptr;
        }
    }
    //缓存区是否满
    bool isFull()
    {
        return m_bFull;
    }
    //判空
    bool isEmpty()
    {
        return m_bEmpty;
    }
    //清空缓存区
    void Clear()
    {
        m_nReadPos = 0;
        m_nWritePos = 0;
        m_bEmpty = true;
        m_bFull = false;
    }
    //获取写入内存的大小
    int GetLength()
    {
        if (m_bEmpty)
        {
            return 0;
        }
        else if (m_bFull)
        {
            return m_nBufSize;
        }
        else if (m_nReadPos < m_nWritePos)
        {
            return m_nWritePos - m_nReadPos;
        }
        else
        {
            return m_nBufSize - m_nReadPos + m_nWritePos;
        }
    }
    //向缓存区中写数据，返回实际写入的字节数
    int Write(T* buf, int count)
    {
        if (count <= 0) 
            return 0;
        m_bEmpty = false;
        // 缓冲区已满，不能继续写入
        if (m_bFull)
        {
            return 0;
        }
        // 缓冲区为空时
        else if (m_nReadPos == m_nWritePos) 
        {
            /*                          == 内存模型 ==
                                        (empty)                    m_nReadPos                (empty)
                                        |----------------------------------|-----------------------------------------|
                                        m_nWritePos                             m_nBufSize
                                        */
            //计算剩余可写入的空间
            int leftcount = m_nBufSize - m_nWritePos;
            if (leftcount > count)
            {
                memcpy(m_pBuf + m_nWritePos, buf, count);
                //尾部位置偏移
                m_nWritePos += count;
                m_bFull = (m_nWritePos == m_nReadPos);
                return count;
            }
            else
            {
                //先把能放下的数据放进缓存区去
                memcpy(m_pBuf + m_nWritePos, buf, leftcount);
                //写指针位置偏移，如果写指针右边的区域能放下剩余数据，就偏移到cont-leftcount位置，
                //否则就偏移到读指针位置，表示缓存区满了，丢弃多余数据
                m_nWritePos = (m_nReadPos > count - leftcount) ? count - leftcount : m_nWritePos;
                //沿着结尾的位置开辟新内存写入剩余的数据
                memcpy(m_pBuf, buf + leftcount, m_nWritePos);
                m_bFull = (m_nWritePos == m_nReadPos);
                return leftcount + m_nWritePos;
            }
        }
        // 有剩余空间，写指针在读指针前面
        else if (m_nReadPos < m_nWritePos) 
        {
            /*                           == 内存模型 ==
                                         (empty)                        (data)                            (empty)
                                         |-------------------|----------------------------|---------------------------|
                                         m_nReadPos                m_nWritePos       (leftcount)
                                         */
            // 计算剩余缓冲区大小(从写入位置到缓冲区尾)
            int leftcount = m_nBufSize - m_nWritePos;
            if (leftcount > count)   // 有足够的剩余空间存放
            {
                //写入缓存区
                memcpy(m_pBuf + m_nWritePos, buf, count);
                //尾部位置偏移
                m_nWritePos += count;
                m_bFull = (m_nReadPos == m_nWritePos);
                assert(m_nReadPos <= m_nBufSize);
                assert(m_nWritePos <= m_nBufSize);
                return count;
            }
            // 写指针右边剩余空间不足以放下数据
            else       
            {
                // 先填充满写指针右边的剩余空间，再看读指针左边能否放下剩余数据
                memcpy(m_pBuf + m_nWritePos, buf, leftcount);
                //写指针位置偏移，如果读指针左边的区域能放下剩余数据，就偏移到cont-leftcount位置，
                //否则就偏移到读指针位置，表示缓存区满了，丢弃多余数据
                m_nWritePos = (m_nReadPos >= count - leftcount) ? count - leftcount : m_nReadPos;
                //沿着结尾位置开辟新内存写入剩余数据
                memcpy(m_pBuf, buf + leftcount, m_nWritePos);
                m_bFull = (m_nReadPos == m_nWritePos);
                assert(m_nReadPos <= m_nBufSize);
                assert(m_nWritePos <= m_nBufSize);
                return leftcount + m_nWritePos;
            }
        }
        //读指针在写指针前面
        else
        {
            /*                          == 内存模型 ==
                                        (unread)                 (read)                     (unread)
                                        |-------------------|----------------------------|---------------------------|
                                        m_nWritePos        (leftcount)         m_nReadPos
                                        */
            int leftcount = m_nReadPos - m_nWritePos;
            if (leftcount > count)
            {
                // 有足够的剩余空间存放
                memcpy(m_pBuf + m_nWritePos, buf, count);
                m_nWritePos += count;
                m_bFull = (m_nReadPos == m_nWritePos);
                assert(m_nReadPos <= m_nBufSize);
                assert(m_nWritePos <= m_nBufSize);
                return count;
            }
            else
            {
                // 剩余空间不足时要丢弃后面的数据
                memcpy(m_pBuf + m_nWritePos, buf, leftcount);
                m_nWritePos += leftcount;
                m_bFull = (m_nReadPos == m_nWritePos);
                assert(m_bFull);
                assert(m_nReadPos <= m_nBufSize);
                assert(m_nWritePos <= m_nBufSize);
                return leftcount;
            }
        }
    }

    //从缓冲区读数据，返回实际读取的字节数       
    int Read(T* buf, int count)
    {
        if (count <= 0) 
            return 0;
        m_bFull = false;
        // 缓冲区空，不能继续读取数据
        if (m_bEmpty)      
        {
            return 0;
        }
        // 缓冲区满时
        else if (m_nReadPos == m_nWritePos)   
        {
            /*                          == 内存模型 ==
                                        (data)                    m_nReadPos                (data)
                                        |--------------------------------|--------------------------------------------|
                                        m_nWritePos         m_nBufSize
                                        */
            int leftcount = m_nBufSize - m_nReadPos;
            if (leftcount > count)
            {
                memcpy(buf, m_pBuf + m_nReadPos, count);
                m_nReadPos += count;
                m_bEmpty = (m_nReadPos == m_nWritePos);
                return count;
            }
            else
            {
                memcpy(buf, m_pBuf + m_nReadPos, leftcount);
                //如果写指针左边的区域能读出剩余数据，就偏移到count-leftcount位置，否则就偏移到
                //写指针位置，表示缓存区空了
                m_nReadPos = (m_nWritePos > count - leftcount) ? count - leftcount : m_nWritePos;
                memcpy(buf + leftcount, m_pBuf, m_nReadPos);
                m_bEmpty = (m_nReadPos == m_nWritePos);
                return leftcount + m_nReadPos;
            }
        }
        // 写指针在前(未读数据是连续的)
        else if (m_nReadPos < m_nWritePos)  
        {
            /*                          == 内存模型 ==
                                        (read)                 (unread)                      (read)
                                        |-------------------|----------------------------|---------------------------|
                                        m_nReadPos                m_nWritePos                     m_nBufSize
                                        */
            int leftcount = m_nWritePos - m_nReadPos;
            int c = (leftcount > count) ? count : leftcount;
            memcpy(buf, m_pBuf + m_nReadPos, c);
            m_nReadPos += c;
            m_bEmpty = (m_nReadPos == m_nWritePos);
            assert(m_nReadPos <= m_nBufSize);
            assert(m_nWritePos <= m_nBufSize);
            return c;
        }
        // 读指针在前
        else         
        {
            /*                          == 内存模型 ==
                                        (unread)                (read)                      (unread)
                                        |-------------------|----------------------------|---------------------------|
                                        m_nWritePos                  m_nReadPos                  m_nBufSize

*/
            int leftcount = m_nBufSize - m_nReadPos;
            // 需要读出的数据是连续的，在读指针右边  m_nReadPos<=count<=m_nBufSize
            if (leftcount > count)   
            {
                memcpy(buf, m_pBuf + m_nReadPos, count);
                m_nReadPos += count;
                m_bEmpty = (m_nReadPos == m_nWritePos);
                assert(m_nReadPos <= m_nBufSize);
                assert(m_nWritePos <= m_nBufSize);
                return count;
            }
            // 需要读出的数据是不连续的，分别在读指针右边和写指针左边
            else       
            {
                //先读出读指针右边的数据
                memcpy(buf, m_pBuf + m_nReadPos, leftcount);
                //位置偏移
                //读指针位置偏移，如果写指针左边的区域能读出剩余数据，就偏移到cont-leftcount位置，
                //否则就偏移到写指针位置，表示缓存区空了，丢弃多余数据
                m_nReadPos = (m_nWritePos >= count - leftcount) ? count - leftcount : m_nWritePos;
                //在读出写指针左边的数据
                memcpy(buf + leftcount, m_pBuf, m_nReadPos);
                m_bEmpty = (m_nReadPos == m_nWritePos);
                assert(m_nReadPos <= m_nBufSize);
                assert(m_nWritePos <= m_nBufSize);
                return leftcount + m_nReadPos;
            }
        }
    }

    //从缓冲区预览数据，返回实际读取的字节数，不改变对象的成员,其实就是Read函数的另一版本
    int Peak(T* buf, int count)
    {
        if (count <= 0) 
            return 0;
        // 缓冲区空，不能继续读取数据
        if (m_bEmpty)      
        {
            return 0;
        }
        // 缓冲区满时
        else if (m_nReadPos == m_nWritePos)   
        {
            /*                          == 内存模型 ==
                                        (data)                    m_nReadPos                (data)
                                        |--------------------------------|--------------------------------------------|
                                        m_nWritePos         m_nBufSize
                                        */
            int leftcount = m_nBufSize - m_nReadPos;
            if (leftcount > count)
            {
                memcpy(buf, m_pBuf + m_nReadPos, count);
                return count;
            }
            else
            {
                memcpy(buf, m_pBuf + m_nReadPos, leftcount);
                //如果写指针左边的区域能读出剩余数据，就偏移到count-leftcount位置，否则就偏移到
                //写指针位置，表示缓存区空了
                int c = (m_nWritePos > count - leftcount) ? count - leftcount : m_nWritePos;
                memcpy(buf + leftcount, m_pBuf, c);
                return leftcount + c;
            }
        }
        // 写指针在前(未读数据是连续的)
        else if (m_nReadPos < m_nWritePos)  
        {
            /*                          == 内存模型 ==
                                        (read)                 (unread)                      (read)
                                        |-------------------|----------------------------|---------------------------|
                                        m_nReadPos                m_nWritePos                     m_nBufSize
                                        */
            int leftcount = m_nWritePos - m_nReadPos;
            int c = (leftcount > count) ? count : leftcount;
            memcpy(buf, m_pBuf + m_nReadPos, c);
            assert(m_nReadPos <= m_nBufSize);
            assert(m_nWritePos <= m_nBufSize);
            return c;
        }
        // 读指针在前
        else         
        {
            /*                          == 内存模型 ==
                                        (unread)                (read)                      (unread)
                                        |-------------------|----------------------------|---------------------------|
                                        m_nWritePos                  m_nReadPos                  m_nBufSize

*/
            int leftcount = m_nBufSize - m_nReadPos;
            // 需要读出的数据是连续的，在读指针右边  m_nReadPos<=count<=m_nBufSize
            if (leftcount > count)   
            {
                memcpy(buf, m_pBuf + m_nReadPos, count);
                assert(m_nReadPos <= m_nBufSize);
                assert(m_nWritePos <= m_nBufSize);
                return count;
            }
            // 需要读出的数据是不连续的，分别在读指针右边和写指针左边
            else       
            {
                //先读出读指针右边的数据
                memcpy(buf, m_pBuf + m_nReadPos, leftcount);
                //位置偏移
                //读指针位置偏移，如果写指针左边的区域能读出剩余数据，就偏移到cont-leftcount位置，
                //否则就偏移到写指针位置，表示缓存区空了，丢弃多余数据
                int c = (m_nWritePos >= count - leftcount) ? count - leftcount : m_nWritePos;
                //在读出写指针左边的数据
                memcpy(buf + leftcount, m_pBuf, c);
                assert(m_nReadPos <= m_nBufSize);
                assert(m_nWritePos <= m_nBufSize);
                return leftcount + c;
            }
        }
    }

    int GetReadPos() 
    { 
        return m_nReadPos; 
    }
    int GetWritePos() 
    { 
        return m_nWritePos; 
    }
private:
    bool m_bEmpty, m_bFull;
    //环形缓存区头指针
    T * m_pBuf=nullptr;
    //环形缓存区大小
    size_t m_nBufSize;
    //可读指针位置（头）
    int m_nReadPos;
    //可写指针位置（尾）
    int m_nWritePos;
};
#endif // !_CIRCLE_BUFFER_HPP_
