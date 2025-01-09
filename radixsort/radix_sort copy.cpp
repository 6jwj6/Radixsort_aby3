#include "aby3/sh3/Sh3Encryptor.h"
#include "aby3/sh3/Sh3Evaluator.h"
#include "aby3/sh3/Sh3Runtime.h"
#include "aby3/sh3/Sh3ShareGen.h"
#include <cryptoTools/Common/CLP.h>
#include "cryptoTools/Common/BitIterator.h"
#include "cryptoTools/Common/Timer.h"
#include "cryptoTools/Crypto/PRNG.h"
#include <cryptoTools/Network/IOService.h>
#include <atomic>
#include "aby3-DB/DBServer.h"
#include <unordered_set>
#include <iostream>

using namespace oc;
using namespace aby3;
using namespace std;

using u32 = uint32_t;
using u64 = uint64_t;

#define fgh cout << "\n---------------------------------\n";
#define foru(i, a, b) for (int i = a; i < b; ++i)
#define ford(i, a, b) for (int i = a; i > b; --i)

i64 Sh3_Int_Vector_test(u64 n)
{
    IOService ios;
    Session s01(ios, "127.0.0.1", SessionMode::Server, "01");
    Session s10(ios, "127.0.0.1", SessionMode::Client, "01");
    Session s02(ios, "127.0.0.1", SessionMode::Server, "02");
    Session s20(ios, "127.0.0.1", SessionMode::Client, "02");
    Session s12(ios, "127.0.0.1", SessionMode::Server, "12");
    Session s21(ios, "127.0.0.1", SessionMode::Client, "12");

    Channel chl01 = s01.addChannel("c");
    Channel chl10 = s10.addChannel("c");
    Channel chl02 = s02.addChannel("c");
    Channel chl20 = s20.addChannel("c");
    Channel chl12 = s12.addChannel("c");
    Channel chl21 = s21.addChannel("c");

    CommPkg comms[3];
    comms[0] = {chl02, chl01};
    comms[1] = {chl10, chl12};
    comms[2] = {chl21, chl20};

    bool failed = false;

    Timer t;
    u32 MOD = 20;
    auto t0 = std::thread([&]()
                          {
                                auto i = 0;
                                vector<i64> a(n);

                                PRNG prng(ZeroBlock);
                                foru(i,0,n) a[i] = prng.get<i64>() % MOD;
                                
                                fgh;
                                cout << "a:\n";
                                foru(i, 0, n) cout << a[i] << " "[i == n - 1];
                                fgh;

                                Sh3Runtime rt(i, comms[i]);

                                vector<si64> A(n);

                                Sh3Encryptor enc;
                                enc.init(i, comms[i],sysRandomSeed());

                                auto task = rt.noDependencies();
                                
                                t.setTimePoint("start");
                                foru(i, 0, n) A[i] = enc.localInt(comms[0], a[i]); // enc.localInt(rt.noDependencies(), a[i], A[i]).get();
                                //cout << "1111" << endl;
                                //cout << "yes " << i << endl;
                                auto x1 = A[0].mData[0], x2 = A[0].mData[1];
                                cout << "shares[" << i << "] = " << (int)x1<<' '<<(int)x2 << endl;
                                i64 res;
                                enc.revealAll(task, A[0], res).get();
                                cout << "res1 = " << (int)res << endl;
                                /*---------------------------------------------------------0线程-----HERE-------*/
                                auto tmp = enc.reshareRemote(comms[0]);
                                // A[0] = A[0] + tmp;
                                comms[0].mPrev.recv(A[0].mData[1]);
                                comms[0].mNext.recv(A[0].mData[0]);
                                //--------------------------------------------------------------

                                enc.revealAll(task, A[0], res).get();
                                cout << "\n0/res2 = " << (int)res << endl;

                                x1 = A[0].mData[0], x2 = A[0].mData[1];

                                cout << "--shares[" << i << "] = " << (int)x1 << ' ' << (int)x2 << endl;

                                Sh3Evaluator eval;
                                eval.init(i, comms[i], sysRandomSeed());

                                t.setTimePoint("eval");
                                vector<si64> C(n);
                                foru(i, 0, n) task = eval.asyncMul(task, A[i], A[i], C[i]);
                                task.get();

                                t.setTimePoint("revealAll");
                                //cout << "1111" << endl;

                                vector<i64> c(n);
                                foru(j, 0, n) c[j] = enc.revealAll(comms[i], C[j]); //(task, C[i], c[i]).get();

                                fgh;
                                foru(i, 0, n) cout << c[i] << " \n"[i == n - 1];
                                fgh;
                                t.setTimePoint("done"); });

    auto routine = [&](int i)
    {
        PRNG prng;

        Sh3Runtime rt(i, comms[i]);

        vector<i64> a(n);

        Sh3Encryptor enc;
        enc.init(i, comms[i], sysRandomSeed());

        auto task = rt.noDependencies();
        vector<si64> A(n);
        // queue up the operations
        foru(j, 0, n) A[j] = enc.remoteInt(comms[i]); // enc.remoteInt(rt.noDependencies(), A[i]).get();
        // cout << "2233" << endl;

        // cout << "yes " << i << endl;
        auto x1 = A[0].mData[0], x2 = A[0].mData[1];
        cout << "shares[" << i << "] = " << (int)x1 << ' ' << (int)x2 << endl;

        i64 res;
        enc.revealAll(task, A[0], res).get();
        cout << "res1 = " << (int)res << endl;
        /*-----------------------------------------------------1/2线程--------------HERE----------------*/
        si64 tmp;
        if (i == 1)
            tmp = enc.reshareLocal(comms[i], 0, 1);
        if (i == 2)
            tmp = enc.reshareLocal(comms[i], 0, 1);
        A[0] = A[0] + tmp;
        if (i == 1)
            comms[1].mPrev.asyncSendCopy(A[0].mData[1]);
        else
            comms[2].mNext.asyncSendCopy(A[0].mData[0]);
        //---------------------------------------------------------------------------------------
        enc.revealAll(task, A[0], res).get();
        cout << "\n"
             << i << "/res2 = " << (int)res << endl;

        x1 = A[0].mData[0], x2 = A[0].mData[1];
        cout << "--shares[" << i << "] = " << (int)x1 << ' ' << (int)x2 << endl;

        Sh3Evaluator eval;
        eval.init(i, comms[i], sysRandomSeed());
        vector<si64> C(n);
        foru(i, 0, n) task = eval.asyncMul(task, A[i], A[i], C[i]);
        task.get();
        // cout << "2233" << endl;
        vector<i64> c(n);
        foru(j, 0, n) c[j] = enc.revealAll(comms[i], C[j]); // enc.revealAll(task, C[i], c[i]).get();
    };

    auto t1 = std::thread(routine, 1);
    auto t2 = std::thread(routine, 2);

    t0.join();
    t1.join();
    t2.join();

    auto comm0 = (comms[0].mNext.getTotalDataSent() + comms[0].mNext.getTotalDataSent());
    auto comm1 = (comms[1].mNext.getTotalDataSent() + comms[1].mNext.getTotalDataSent());
    auto comm2 = (comms[2].mNext.getTotalDataSent() + comms[2].mNext.getTotalDataSent());
    std::cout << "n = " << n << "   " << comm0 + comm1 + comm2 << "\n"
              << t << std::endl;

    if (failed)
        throw std::runtime_error(LOCATION);

    return 0;
}

signed main()
{
    // Sh3_Bin_add_test(3);
    // Sh3_Int_Matrix_test(2, 2);
    Sh3_Int_Vector_test(10);
    return 0;
}