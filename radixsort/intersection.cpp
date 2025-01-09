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

#define foru(i, a, b) for (int i = a; i < b; ++i)
#define ford(i, a, b) for (int i = a; i > b; --i)

using namespace oc;
using namespace aby3;
using namespace std;

using u32 = uint32_t;
using u64 = uint64_t;

void DB_Intersect(u32 rows, u32 cols, bool sum)
{
    using namespace aby3;
    IOService ios;
    Session s01(ios, "127.0.0.1", SessionMode::Server, "01");
    Session s10(ios, "127.0.0.1", SessionMode::Client, "01");
    Session s02(ios, "127.0.0.1", SessionMode::Server, "02");
    Session s20(ios, "127.0.0.1", SessionMode::Client, "02");
    Session s12(ios, "127.0.0.1", SessionMode::Server, "12");
    Session s21(ios, "127.0.0.1", SessionMode::Client, "12");

    PRNG prng(oc::ZeroBlock);
    DBServer srvs[3];
    srvs[0].init(0, s02, s01, prng);
    srvs[1].init(1, s10, s12, prng);
    srvs[2].init(2, s21, s20, prng);

    // 80 bits;
    // u32 hashSize = 80;

    auto keyBitCount = srvs[0].mKeyBitCount;
    cout << "keyBitCount = " << keyBitCount << endl;

    std::vector<ColumnInfo>
        aCols = {ColumnInfo{"key", TypeID::IntID, keyBitCount}},
        bCols = {ColumnInfo{"key", TypeID::IntID, keyBitCount}};

    for (u32 i = 0; i < cols; ++i)
    {
        // aCols.emplace_back("a" + std::to_string(i), TypeID::IntID, 32);
        bCols.emplace_back("b" + std::to_string(i), TypeID::IntID, 32);
    }

    Table a(rows, aCols), b(rows, bCols);
    auto intersectionSize = (rows + 1) / 2;
    // cout << "a.mColumns[0].mData.cols() = " << a.mColumns[0].mData.cols() << endl;
    cout << "a.mColumns[0].mData.rows() = " << a.mColumns[0].mData.rows() << endl;

    for (u64 i = 0; i < rows; ++i)
    {
        auto out = (i >= intersectionSize);
        for (u64 j = 0; j < (u64)a.mColumns[0].mData.cols(); ++j)
        {
            a.mColumns[0].mData(i, j) = i + 1;
            b.mColumns[0].mData(i, j) = i + 1 + (rows * out);
            cout << "tttest i = " << i << ",j = " << j << ": "
                 << a.mColumns[0].mData(i, j) << ' ' << b.mColumns[0].mData(i, j) << endl;
        }
    }

    Timer t;

    bool failed = false;
    auto routine = [&](int i)
    {
        cout << "routine = " << i << endl;

        setThreadName("t0");
        t.setTimePoint("start");

        auto A = (i == 0) ? srvs[i].localInput(a) : srvs[i].remoteInput(0);
        auto B = (i == 0) ? srvs[i].localInput(b) : srvs[i].remoteInput(0);
        if (i == 0)
            t.setTimePoint("inputs");

        if (i == 0)
            srvs[i].setTimer(t);

        SelectQuery query;
        query.noReveal("r");
        auto aKey = query.joinOn(A["key"], B["key"]);
        query.addOutput("key", aKey);

        // for (u32 i = 0; i < cols; ++i)
        // {
        //     // query.addOutput("a" + std::to_string(i), query.addInput(A["a" + std::to_string(i)]));
        //     // query.addOutput("b" + std::to_string(i), query.addInput(B["b" + std::to_string(i)]));
        // }

        cout << "pre_C yes" << endl;
        auto C = srvs[i].joinImpl(query);

        cout << "C.rows() = " << C.rows() << endl;

        if (i == 0)
            t.setTimePoint("intersect");

        if (sum)
        {
            Sh3BinaryEvaluator eval;

            BetaLibrary lib;
            BetaCircuit *cir = lib.int_int_add(64, 64, 64);

            auto task = srvs[i].mRt.noDependencies();

            sbMatrix AA(C.rows(), 64), BB(C.rows(), 64), CC(C.rows(), 64);
            task = eval.asyncEvaluate(task, cir, srvs[i].mEnc.mShareGen, {&AA, &BB}, {&CC});

            std::cout << 222 << std::endl;
            Sh3Encryptor enc;
            // if (i == 0)
            // {
            //     i64Matrix m(C.rows(), 2);
            //     std::cout << "i = " << i << ' ' << 323 << std::endl;
            //     enc.reveal(task, CC, m).get();
            //     std::cout << 333 << std::endl;
            //     // std::cout << "yes!";
            //     // std::cout << "m = " << m;
            // }
            // else
            // {
            //     enc.reveal(task, 0, CC).get();
            //     cout << 333 << endl;
            // }
            // t.setTimePoint("sum");

            i64Matrix m(C.rows(), 1);
            srvs[i].mEnc.revealAll(task, CC, m).get();
            std::cout << "m = " << m << std::endl;
            std::cout << "i = " << i << ' ' << 444 << std::endl;
        }
        else if (C.rows())
        {
            using namespace std;
            aby3::i64Matrix c(C.mColumns[0].rows(), C.mColumns[0].i64Cols());
            cout << "c.cols() = " << c.cols() << endl;

            srvs[i].mEnc.revealAll(srvs[i].mRt.mComm, C.mColumns[0], c);
            cout << "i = " << i << endl;
            cout << "\n-------------------------\n"
                 << "c = \n"
                 << c << "\n-------------------------\n";
            foru(i, 0, c.rows()) foru(j, 0, c.cols()) cout << c.row(i).col(j) << ' ';
            cout << endl;

            if (i == 0)
                t.setTimePoint("reveal");
        }
        else
        {
            failed = true;
        }
        // std::cout << t << std::endl << srvs[i].getTimer() << std::endl;
    };

    auto t0 = std::thread(routine, 0);
    auto t1 = std::thread(routine, 1);
    // auto t2 = std::thread(routine, 2);

    routine(2);
    t0.join();
    t1.join();

    auto comm0 = (srvs[0].mRt.mComm.mNext.getTotalDataSent() + srvs[0].mRt.mComm.mPrev.getTotalDataSent());
    auto comm1 = (srvs[1].mRt.mComm.mNext.getTotalDataSent() + srvs[1].mRt.mComm.mPrev.getTotalDataSent());
    auto comm2 = (srvs[2].mRt.mComm.mNext.getTotalDataSent() + srvs[2].mRt.mComm.mPrev.getTotalDataSent());
    cout << "\n----------------------------------------------------------\n";
    std::cout << "n = " << rows << "   " << comm0 + comm1 + comm2 << "\n"
              << t << std::endl;

    if (failed)
    {
        std::cout << "bad intersection" << std::endl;
        throw std::runtime_error("");
    }
}

int main()
{
    try
    {
        // 调用 DB_Intersect 函数，参数根据需求调整
        DB_Intersect(3, 2, false); // 100 行数据，2 列，关闭 sum 功能
    }
    catch (const std::exception &ex)
    {
        std::cerr << "Error: " << ex.what() << std::endl;
    }
    return 0;
}