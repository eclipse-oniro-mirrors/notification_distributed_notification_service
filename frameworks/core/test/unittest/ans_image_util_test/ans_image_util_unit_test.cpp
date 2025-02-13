 /*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <gtest/gtest.h>

#define private public
#define protected public
#include "ans_image_util.h"
#include "image_packer.h"
#include "pixel_map.h"
#undef private
#undef protected

using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::Notification;

extern void MockImagePackerGetSupportedFormats(uint32_t mockRet);
extern void MockImagePackerStartPacking(const uint8_t* mockRet);
extern void MockImagePackerFinalizePacking(uint32_t mockRet);
extern void MockResetImagePackerState();

extern void MockImageSourceCreateImageSource(bool mockRet, uint32_t errorCode);
extern void MockImageSourceCreatePixelMap(bool mockRet, uint32_t errorCode);
extern void MockImageSourceGetSupportedFormats(uint32_t mockRet);
extern void MockResetImageSourceState();

extern void MockPixelMapGetByteCount(int32_t mockRet);
extern void MockResetPixelMapState();

class AnsImageUtilUnitTest : public testing::Test {
public:
    AnsImageUtilUnitTest() {}

    virtual ~AnsImageUtilUnitTest() {}

    static void SetUpTestCase();

    static void TearDownTestCase();

    void SetUp();

    void TearDown();
};

void AnsImageUtilUnitTest::SetUpTestCase() {}

void AnsImageUtilUnitTest::TearDownTestCase() {}

void AnsImageUtilUnitTest::SetUp() {}

void AnsImageUtilUnitTest::TearDown() {}

/*
 * @tc.name: PackImageTest_0100
 * @tc.desc: test if AnsImageUtil's PackImage function executed as expected in normal case.
 * @tc.type: FUNC
 * @tc.require: #I5SJ62
 */
HWTEST_F(AnsImageUtilUnitTest, PackImageTest_0100, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsImageUtilUnitTest, PackImageTest_0100, TestSize.Level1";
    MockImagePackerGetSupportedFormats(0);
    const uint8_t testBitmap[16] = "101"; // 16 : size of testbitmap
    MockImagePackerStartPacking(testBitmap);
    std::shared_ptr<AnsImageUtil> imageUtil = std::make_shared<AnsImageUtil>();
    ASSERT_NE(nullptr, imageUtil);
    std::shared_ptr<Media::PixelMap> pixelMap = std::make_shared<Media::PixelMap>();
    ASSERT_NE(nullptr, pixelMap);
    std::string format = ":";
    std::string res = imageUtil->PackImage(pixelMap, format);
    EXPECT_FALSE(res.empty());
    MockResetImagePackerState();
    MockResetPixelMapState();
}

/*
 * @tc.name: PackImageTest_0200
 * @tc.desc: test if AnsImageUtil's PackImage function.
 * @tc.type: FUNC
 * @tc.require: #I5SJ62
 */
HWTEST_F(AnsImageUtilUnitTest, PackImageTest_0200, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsImageUtilUnitTest, PackImageTest_0200, TestSize.Level1";
    std::shared_ptr<AnsImageUtil> imageUtil = std::make_shared<AnsImageUtil>();
    ASSERT_NE(nullptr, imageUtil);
    std::string format = ":";
    std::string res = imageUtil->PackImage(nullptr, format);
    EXPECT_TRUE(res.empty());
}

/*
 * @tc.name: PackImageTest_0300
 * @tc.desc: test if AnsImageUtil's PackImage function.
 * @tc.type: FUNC
 * @tc.require: #I5SJ62
 */
HWTEST_F(AnsImageUtilUnitTest, PackImageTest_0300, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsImageUtilUnitTest, PackImageTest_0300, TestSize.Level1";
    std::shared_ptr<AnsImageUtil> imageUtil = std::make_shared<AnsImageUtil>();
    ASSERT_NE(nullptr, imageUtil);
    std::shared_ptr<Media::PixelMap> pixelMap = std::make_shared<Media::PixelMap>();
    ASSERT_NE(nullptr, pixelMap);
    std::string res = imageUtil->PackImage(pixelMap, "");
    EXPECT_TRUE(res.empty());
}

/*
 * @tc.name: PackImageTest_0400
 * @tc.desc: test if AnsImageUtil's PackImage function.
 * @tc.type: FUNC
 * @tc.require: #I5SJ62
 */
HWTEST_F(AnsImageUtilUnitTest, PackImageTest_0400, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsImageUtilUnitTest, PackImageTest_0400, TestSize.Level1";
    MockImagePackerGetSupportedFormats(1);
    const uint8_t testBitmap[16] = "101"; // 16 : size of testbitmap
    MockImagePackerStartPacking(testBitmap);
    std::shared_ptr<AnsImageUtil> imageUtil = std::make_shared<AnsImageUtil>();
    ASSERT_NE(nullptr, imageUtil);
    std::shared_ptr<Media::PixelMap> pixelMap = std::make_shared<Media::PixelMap>();
    ASSERT_NE(nullptr, pixelMap);
    std::string format = ":";
    std::string res = imageUtil->PackImage(pixelMap, format);
    EXPECT_TRUE(res.empty());
    MockResetImagePackerState();
    MockResetPixelMapState();
}

/*
 * @tc.name: UnPackImageTest_0100
 * @tc.desc: test if AnsImageUtil's UnPackImage function.
 * @tc.type: FUNC
 * @tc.require: #I5SJ62
 */
HWTEST_F(AnsImageUtilUnitTest, UnPackImageTest_0100, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsImageUtilUnitTest, UnPackImageTest_0100, TestSize.Level1";
    MockImageSourceCreateImageSource(true, 0);
    MockImageSourceCreatePixelMap(true, 0);
    std::shared_ptr<AnsImageUtil> imageUtil = std::make_shared<AnsImageUtil>();
    ASSERT_NE(nullptr, imageUtil);
    std::string pixelMapStr = "101";
    std::shared_ptr<Media::PixelMap> res = imageUtil->UnPackImage(pixelMapStr);
    EXPECT_NE(nullptr, res);
    MockResetImageSourceState();
}

/*
 * @tc.name: UnPackImageTest_0200
 * @tc.desc: test if AnsImageUtil's UnPackImage function.
 * @tc.type: FUNC
 * @tc.require: #I5SJ62
 */
HWTEST_F(AnsImageUtilUnitTest, UnPackImageTest_0200, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsImageUtilUnitTest, UnPackImageTest_0200, TestSize.Level1";
    MockImageSourceCreateImageSource(true, 0);
    MockImageSourceCreatePixelMap(true, 0);
    std::shared_ptr<AnsImageUtil> imageUtil = std::make_shared<AnsImageUtil>();
    ASSERT_NE(nullptr, imageUtil);
    std::string pixelMapStr = "";
    std::shared_ptr<Media::PixelMap> res = imageUtil->UnPackImage(pixelMapStr);
    EXPECT_EQ(nullptr, res);
    MockResetImageSourceState();
}

/*
 * @tc.name: UnPackImageTest_0300
 * @tc.desc: test if AnsImageUtil's UnPackImage function.
 * @tc.type: FUNC
 * @tc.require: #I5SJ62
 */
HWTEST_F(AnsImageUtilUnitTest, UnPackImageTest_0300, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsImageUtilUnitTest, UnPackImageTest_0300, TestSize.Level1";
    MockImageSourceCreateImageSource(false, 0);
    MockImageSourceCreatePixelMap(true, 0);
    std::shared_ptr<AnsImageUtil> imageUtil = std::make_shared<AnsImageUtil>();
    ASSERT_NE(nullptr, imageUtil);
    std::string pixelMapStr = "101";
    std::shared_ptr<Media::PixelMap> res = imageUtil->UnPackImage(pixelMapStr);
    EXPECT_EQ(nullptr, res);
    MockResetImageSourceState();
}

/*
 * @tc.name: UnPackImageTest_0400
 * @tc.desc: test if AnsImageUtil's UnPackImage function.
 * @tc.type: FUNC
 * @tc.require: #I5SJ62
 */
HWTEST_F(AnsImageUtilUnitTest, UnPackImageTest_0400, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsImageUtilUnitTest, UnPackImageTest_0400, TestSize.Level1";
    MockImageSourceCreateImageSource(true, 1);
    MockImageSourceCreatePixelMap(true, 0);
    std::shared_ptr<AnsImageUtil> imageUtil = std::make_shared<AnsImageUtil>();
    ASSERT_NE(nullptr, imageUtil);
    std::string pixelMapStr = "101";
    std::shared_ptr<Media::PixelMap> res = imageUtil->UnPackImage(pixelMapStr);
    EXPECT_EQ(nullptr, res);
    MockResetImageSourceState();
}

/*
 * @tc.name: UnPackImageTest_0500
 * @tc.desc: test if AnsImageUtil's UnPackImage function.
 * @tc.type: FUNC
 * @tc.require: #I5SJ62
 */
HWTEST_F(AnsImageUtilUnitTest, UnPackImageTest_0500, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsImageUtilUnitTest, UnPackImageTest_0500, TestSize.Level1";
    MockImageSourceCreateImageSource(true, 0);
    MockImageSourceCreatePixelMap(false, 0);
    std::shared_ptr<AnsImageUtil> imageUtil = std::make_shared<AnsImageUtil>();
    ASSERT_NE(nullptr, imageUtil);
    std::string pixelMapStr = "101";
    std::shared_ptr<Media::PixelMap> res = imageUtil->UnPackImage(pixelMapStr);
    EXPECT_EQ(nullptr, res);
    MockResetImageSourceState();
}

/*
 * @tc.name: UnPackImageTest_0600
 * @tc.desc: test if AnsImageUtil's UnPackImage function.
 * @tc.type: FUNC
 * @tc.require: #I5SJ62
 */
HWTEST_F(AnsImageUtilUnitTest, UnPackImageTest_0600, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsImageUtilUnitTest, UnPackImageTest_0600, TestSize.Level1";
    MockImageSourceCreateImageSource(true, 0);
    MockImageSourceCreatePixelMap(true, 1);
    std::shared_ptr<AnsImageUtil> imageUtil = std::make_shared<AnsImageUtil>();
    ASSERT_NE(nullptr, imageUtil);
    std::string pixelMapStr = "101";
    std::shared_ptr<Media::PixelMap> res = imageUtil->UnPackImage(pixelMapStr);
    EXPECT_EQ(nullptr, res);
    MockResetImageSourceState();
}

/*
 * @tc.name: PackImage2FileTest_0100
 * @tc.desc: test if AnsImageUtil's PackImage2File function.
 * @tc.type: FUNC
 * @tc.require: #I5SJ62
 */
HWTEST_F(AnsImageUtilUnitTest, PackImage2FileTest_0100, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsImageUtilUnitTest, PackImage2FileTest_0100, TestSize.Level1";
    MockImagePackerGetSupportedFormats(0);
    std::shared_ptr<AnsImageUtil> imageUtil = std::make_shared<AnsImageUtil>();
    ASSERT_NE(nullptr, imageUtil);
    std::shared_ptr<Media::PixelMap> pixelMap = std::make_shared<Media::PixelMap>();
    std::string outFilePath = "testPath";
    std::string format = "testFormat";
    bool res = imageUtil->PackImage2File(pixelMap, outFilePath, format);
    EXPECT_TRUE(res);
    MockResetImagePackerState();
}

/*
 * @tc.name: PackImage2FileTest_0200
 * @tc.desc: test if AnsImageUtil's PackImage2File function.
 * @tc.type: FUNC
 * @tc.require: #I5SJ62
 */
HWTEST_F(AnsImageUtilUnitTest, PackImage2FileTest_0200, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsImageUtilUnitTest, PackImage2FileTest_0200, TestSize.Level1";
    MockImagePackerGetSupportedFormats(0);
    std::shared_ptr<AnsImageUtil> imageUtil = std::make_shared<AnsImageUtil>();
    ASSERT_NE(nullptr, imageUtil);
    std::shared_ptr<Media::PixelMap> pixelMap = nullptr;
    std::string outFilePath = "testPath";
    std::string format = "testFormat";
    bool res = imageUtil->PackImage2File(pixelMap, outFilePath, format);
    EXPECT_FALSE(res);
    MockResetImagePackerState();
}

/*
 * @tc.name: PackImage2FileTest_0300
 * @tc.desc: test if AnsImageUtil's PackImage2File function.
 * @tc.type: FUNC
 * @tc.require: #I5SJ62
 */
HWTEST_F(AnsImageUtilUnitTest, PackImage2FileTest_0300, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsImageUtilUnitTest, PackImage2FileTest_0300, TestSize.Level1";
    MockImagePackerGetSupportedFormats(0);
    std::shared_ptr<AnsImageUtil> imageUtil = std::make_shared<AnsImageUtil>();
    ASSERT_NE(nullptr, imageUtil);
    std::shared_ptr<Media::PixelMap> pixelMap = std::make_shared<Media::PixelMap>();
    std::string outFilePath = "";
    std::string format = "testFormat";
    bool res = imageUtil->PackImage2File(pixelMap, outFilePath, format);
    EXPECT_FALSE(res);
    MockResetImagePackerState();
}

/*
 * @tc.name: PackImage2FileTest_0400
 * @tc.desc: test if AnsImageUtil's PackImage2File function.
 * @tc.type: FUNC
 * @tc.require: #I5SJ62
 */
HWTEST_F(AnsImageUtilUnitTest, PackImage2FileTest_0400, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsImageUtilUnitTest, PackImage2FileTest_0400, TestSize.Level1";
    MockImagePackerGetSupportedFormats(0);
    std::shared_ptr<AnsImageUtil> imageUtil = std::make_shared<AnsImageUtil>();
    ASSERT_NE(nullptr, imageUtil);
    std::shared_ptr<Media::PixelMap> pixelMap = std::make_shared<Media::PixelMap>();
    std::string outFilePath = "testPath";
    std::string format = "";
    bool res = imageUtil->PackImage2File(pixelMap, outFilePath, format);
    EXPECT_FALSE(res);
    MockResetImagePackerState();
}

/*
 * @tc.name: PackImage2FileTest_0500
 * @tc.desc: test if AnsImageUtil's PackImage2File function.
 * @tc.type: FUNC
 * @tc.require: #I5SJ62
 */
HWTEST_F(AnsImageUtilUnitTest, PackImage2FileTest_0500, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsImageUtilUnitTest, PackImage2FileTest_0500, TestSize.Level1";
    MockImagePackerGetSupportedFormats(1);
    std::shared_ptr<AnsImageUtil> imageUtil = std::make_shared<AnsImageUtil>();
    ASSERT_NE(nullptr, imageUtil);
    std::shared_ptr<Media::PixelMap> pixelMap = std::make_shared<Media::PixelMap>();
    std::string outFilePath = "testPath";
    std::string format = "testFormat";
    bool res = imageUtil->PackImage2File(pixelMap, outFilePath, format);
    EXPECT_FALSE(res);
    MockResetImagePackerState();
}

/*
 * @tc.name: CreatePixelMapTest_0100
 * @tc.desc: test if AnsImageUtil's CreatePixelMap function.
 * @tc.type: FUNC
 * @tc.require: #I5SJ62
 */
HWTEST_F(AnsImageUtilUnitTest, CreatePixelMapTest_0100, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsImageUtilUnitTest, CreatePixelMapTest_0100, TestSize.Level1";
    MockImageSourceCreateImageSource(true, 0);
    MockImageSourceGetSupportedFormats(0);
    MockImageSourceCreatePixelMap(true, 0);
    std::shared_ptr<AnsImageUtil> imageUtil = std::make_shared<AnsImageUtil>();
    ASSERT_NE(nullptr, imageUtil);
    std::string inFilePath = "testInfile";
    std::string format = "testFormat";
    std::shared_ptr<Media::PixelMap> res = imageUtil->CreatePixelMap(inFilePath, format);
    EXPECT_NE(nullptr, res);
    MockResetImageSourceState();
    MockResetImagePackerState();
}

/*
 * @tc.name: CreatePixelMapTest_0200
 * @tc.desc: test if AnsImageUtil's CreatePixelMap function.
 * @tc.type: FUNC
 * @tc.require: #I5SJ62
 */
HWTEST_F(AnsImageUtilUnitTest, CreatePixelMapTest_0200, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsImageUtilUnitTest, CreatePixelMapTest_0200, TestSize.Level1";
    MockImageSourceCreateImageSource(true, 0);
    MockImageSourceGetSupportedFormats(0);
    MockImageSourceCreatePixelMap(true, 0);
    std::shared_ptr<AnsImageUtil> imageUtil = std::make_shared<AnsImageUtil>();
    ASSERT_NE(nullptr, imageUtil);
    std::string inFilePath = "";
    std::string format = "testFormat";
    std::shared_ptr<Media::PixelMap> res = imageUtil->CreatePixelMap(inFilePath, format);
    EXPECT_EQ(nullptr, res);
    MockResetImageSourceState();
    MockResetImagePackerState();
}

/*
 * @tc.name: CreatePixelMapTest_0300
 * @tc.desc: test if AnsImageUtil's CreatePixelMap function.
 * @tc.type: FUNC
 * @tc.require: #I5SJ62
 */
HWTEST_F(AnsImageUtilUnitTest, CreatePixelMapTest_0300, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsImageUtilUnitTest, CreatePixelMapTest_0300, TestSize.Level1";
    MockImageSourceCreateImageSource(true, 0);
    MockImageSourceGetSupportedFormats(0);
    MockImageSourceCreatePixelMap(true, 0);
    std::shared_ptr<AnsImageUtil> imageUtil = std::make_shared<AnsImageUtil>();
    ASSERT_NE(nullptr, imageUtil);
    std::string inFilePath = "testInfile";
    std::string format = "";
    std::shared_ptr<Media::PixelMap> res = imageUtil->CreatePixelMap(inFilePath, format);
    EXPECT_EQ(nullptr, res);
    MockResetImageSourceState();
    MockResetImagePackerState();
}


/*
 * @tc.name: CreatePixelMapTest_0400
 * @tc.desc: test if AnsImageUtil's CreatePixelMap function.
 * @tc.type: FUNC
 * @tc.require: #I5SJ62
 */
HWTEST_F(AnsImageUtilUnitTest, CreatePixelMapTest_0400, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsImageUtilUnitTest, CreatePixelMapTest_0400, TestSize.Level1";
    MockImageSourceCreateImageSource(false, 0);
    MockImageSourceGetSupportedFormats(0);
    MockImageSourceCreatePixelMap(true, 0);
    std::shared_ptr<AnsImageUtil> ansImageUtil = std::make_shared<AnsImageUtil>();
    ASSERT_NE(nullptr, ansImageUtil);
    std::string testInfile = "testInfile";
    std::string testFormat = "testFormat";
    std::shared_ptr<Media::PixelMap> res = ansImageUtil->CreatePixelMap(testInfile, testFormat);
    EXPECT_EQ(nullptr, res);
    MockResetImageSourceState();
    MockResetImagePackerState();
}

/*
 * @tc.name: CreatePixelMapTest_0500
 * @tc.desc: test if AnsImageUtil's CreatePixelMap function.
 * @tc.type: FUNC
 * @tc.require: #I5SJ62
 */
HWTEST_F(AnsImageUtilUnitTest, CreatePixelMapTest_0500, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsImageUtilUnitTest, CreatePixelMapTest_0500, TestSize.Level1";
    MockImageSourceCreateImageSource(true, 1);
    MockImageSourceGetSupportedFormats(0);
    MockImageSourceCreatePixelMap(true, 0);
    std::shared_ptr<AnsImageUtil> imageUtil = std::make_shared<AnsImageUtil>();
    ASSERT_NE(nullptr, imageUtil);
    std::string inFilePath = "testInfile";
    std::string format = "testFormat";
    std::shared_ptr<Media::PixelMap> res = imageUtil->CreatePixelMap(inFilePath, format);
    EXPECT_EQ(nullptr, res);
    MockResetImageSourceState();
    MockResetImagePackerState();
}

/*
 * @tc.name: CreatePixelMapTest_0600
 * @tc.desc: test if AnsImageUtil's CreatePixelMap function.
 * @tc.type: FUNC
 * @tc.require: #I5SJ62
 */
HWTEST_F(AnsImageUtilUnitTest, CreatePixelMapTest_0600, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsImageUtilUnitTest, CreatePixelMapTest_0600, TestSize.Level1";
    MockImageSourceCreateImageSource(true, 0);
    MockImageSourceGetSupportedFormats(1);
    MockImageSourceCreatePixelMap(true, 0);
    std::shared_ptr<AnsImageUtil> imageUtil = std::make_shared<AnsImageUtil>();
    ASSERT_NE(nullptr, imageUtil);
    std::string inFilePath = "testInfile";
    std::string format = "testFormat";
    std::shared_ptr<Media::PixelMap> res = imageUtil->CreatePixelMap(inFilePath, format);
    EXPECT_EQ(nullptr, res);
    MockResetImageSourceState();
}

/*
 * @tc.name: CreatePixelMapTest_0700
 * @tc.desc: test if AnsImageUtil's CreatePixelMap function.
 * @tc.type: FUNC
 * @tc.require: #I5SJ62
 */
HWTEST_F(AnsImageUtilUnitTest, CreatePixelMapTest_0700, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsImageUtilUnitTest, CreatePixelMapTest_0700, TestSize.Level1";
    MockImageSourceCreateImageSource(true, 0);
    MockImageSourceGetSupportedFormats(0);
    MockImageSourceCreatePixelMap(false, 0);
    std::shared_ptr<AnsImageUtil> imageUtil = std::make_shared<AnsImageUtil>();
    ASSERT_NE(nullptr, imageUtil);
    std::string inFilePath = "testInfile";
    std::string format = "testFormat";
    std::shared_ptr<Media::PixelMap> res = imageUtil->CreatePixelMap(inFilePath, format);
    EXPECT_EQ(nullptr, res);
    MockResetImageSourceState();
    MockResetImagePackerState();
}

/*
 * @tc.name: CreatePixelMapTest_0800
 * @tc.desc: test if AnsImageUtil's CreatePixelMap function.
 * @tc.type: FUNC
 * @tc.require: #I5SJ62
 */
HWTEST_F(AnsImageUtilUnitTest, CreatePixelMapTest_0800, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsImageUtilUnitTest, CreatePixelMapTest_0800, TestSize.Level1";
    MockImageSourceCreateImageSource(true, 0);
    MockImageSourceGetSupportedFormats(0);
    MockImageSourceCreatePixelMap(true, 1);
    std::shared_ptr<AnsImageUtil> imageUtil = std::make_shared<AnsImageUtil>();
    ASSERT_NE(nullptr, imageUtil);
    std::string inFilePath = "testInfile";
    std::string format = "testFormat";
    std::shared_ptr<Media::PixelMap> res = imageUtil->CreatePixelMap(inFilePath, format);
    EXPECT_EQ(nullptr, res);
    MockResetImageSourceState();
    MockResetImagePackerState();
}

/*
 * @tc.name: BinToHexTest_0100
 * @tc.desc: test if AnsImageUtil's BinToHex function.
 * @tc.type: FUNC
 * @tc.require: #I5SJ62
 */
HWTEST_F(AnsImageUtilUnitTest, BinToHexTest_0100, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsImageUtilUnitTest, BinToHexTest_0100, TestSize.Level1";
    std::shared_ptr<AnsImageUtil> imageUtil = std::make_shared<AnsImageUtil>();
    ASSERT_NE(nullptr, imageUtil);
    std::string strBin = "12112221";
    std::string res = imageUtil->HexToBin(strBin);
    EXPECT_NE("", res);
}

/*
 * @tc.name: BinToHexTest_0200
 * @tc.desc: test if AnsImageUtil's BinToHex function.
 * @tc.type: FUNC
 * @tc.require: #I5SJ62
 */
HWTEST_F(AnsImageUtilUnitTest, BinToHexTest_0200, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsImageUtilUnitTest, BinToHexTest_0200, TestSize.Level1";
    std::shared_ptr<AnsImageUtil> imageUtil = std::make_shared<AnsImageUtil>();
    ASSERT_NE(nullptr, imageUtil);
    std::string strBin = "";
    std::string res = imageUtil->HexToBin(strBin);
    EXPECT_EQ("", res);
}

/*
 * @tc.name: HexToBinTest_0100
 * @tc.desc: test if AnsImageUtil's HexToBin function.
 * @tc.type: FUNC
 * @tc.require: #I5SJ62
 */
HWTEST_F(AnsImageUtilUnitTest, HexToBinTest_0100, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsImageUtilUnitTest, HexToBinTest_0100, TestSize.Level1";
    std::shared_ptr<AnsImageUtil> imageUtil = std::make_shared<AnsImageUtil>();
    ASSERT_NE(nullptr, imageUtil);
    std::string strHex = "12112221";
    std::string res = imageUtil->HexToBin(strHex);
    EXPECT_NE("", res);
}

/*
 * @tc.name: HexToBinTest_0200
 * @tc.desc: test if AnsImageUtil's HexToBin function.
 * @tc.type: FUNC
 * @tc.require: #I5SJ62
 */
HWTEST_F(AnsImageUtilUnitTest, HexToBinTest_0200, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsImageUtilUnitTest, HexToBinTest_0200, TestSize.Level1";
    std::shared_ptr<AnsImageUtil> imageUtil = std::make_shared<AnsImageUtil>();
    ASSERT_NE(nullptr, imageUtil);
    std::string strHex = "";
    std::string res = imageUtil->HexToBin(strHex);
    EXPECT_EQ("", res);
}

/*
 * @tc.name: HexToBinTest_0300
 * @tc.desc: test if AnsImageUtil's HexToBin function.
 * @tc.type: FUNC
 * @tc.require: #I5SJ62
 */
HWTEST_F(AnsImageUtilUnitTest, HexToBinTest_0300, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsImageUtilUnitTest, HexToBinTest_0300, TestSize.Level1";
    std::shared_ptr<AnsImageUtil> imageUtil = std::make_shared<AnsImageUtil>();
    ASSERT_NE(nullptr, imageUtil);
    std::string strHex = "123";
    std::string res = imageUtil->HexToBin(strHex);
    EXPECT_EQ("", res);
}

/*
 * @tc.name: HexToBinTest_0400
 * @tc.desc: test if AnsImageUtil's HexToBin function.
 * @tc.type: FUNC
 * @tc.require: #I5SJ62
 */
HWTEST_F(AnsImageUtilUnitTest, HexToBinTest_0400, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsImageUtilUnitTest, HexToBinTest_0400, TestSize.Level1";
    std::shared_ptr<AnsImageUtil> imageUtil = std::make_shared<AnsImageUtil>();
    ASSERT_NE(nullptr, imageUtil);
    std::string strHex = "123x";
    std::string res = imageUtil->HexToBin(strHex);
    EXPECT_EQ("", res);
}

/*
 * @tc.name: ImageScale_0100
 * @tc.desc: test if AnsImageUtil's ImageScale function.
 * @tc.type: FUNC
 * @tc.require: #I5SJ62
 */
HWTEST_F(AnsImageUtilUnitTest, ImageScale_0100, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsImageUtilUnitTest, ImageScale_0100, TestSize.Level1";
    std::shared_ptr<AnsImageUtil> imageUtil = std::make_shared<AnsImageUtil>();
    ASSERT_NE(nullptr, imageUtil);
    bool res = imageUtil->ImageScale(nullptr, 0, 0);
    EXPECT_FALSE(res);
}

/*
 * @tc.name: ImageScale_0200
 * @tc.desc: test if AnsImageUtil's ImageScale function.
 * @tc.type: FUNC
 * @tc.require: #I5SJ62
 */
HWTEST_F(AnsImageUtilUnitTest, ImageScale_0200, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsImageUtilUnitTest, ImageScale_0200, TestSize.Level1";
    std::shared_ptr<AnsImageUtil> imageUtil = std::make_shared<AnsImageUtil>();
    ASSERT_NE(nullptr, imageUtil);
    std::shared_ptr<Media::PixelMap> pixelMap = std::make_shared<Media::PixelMap>();
    ASSERT_NE(nullptr, pixelMap);
    bool res = imageUtil->ImageScale(pixelMap, 60, 60);
    EXPECT_FALSE(res);
}

/*
 * @tc.name: CreatePixelMapByString_0100
 * @tc.desc: test if AnsImageUtil's CreatePixelMapByString function.
 * @tc.type: FUNC
 * @tc.require: #I5SJ62
 */
HWTEST_F(AnsImageUtilUnitTest, CreatePixelMapByString_0100, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsImageUtilUnitTest, CreatePixelMapByString_0100, TestSize.Level1";
    std::shared_ptr<AnsImageUtil> imageUtil = std::make_shared<AnsImageUtil>();
    ASSERT_NE(nullptr, imageUtil);
    std::string path = "";
    std::shared_ptr<Media::PixelMap> res = imageUtil->CreatePixelMapByString(path);
    EXPECT_EQ(nullptr, res);
}

/*
 * @tc.name: CreatePixelMapByString_0200
 * @tc.desc: test if AnsImageUtil's CreatePixelMapByString function.
 * @tc.type: FUNC
 * @tc.require: #I5SJ62
 */
HWTEST_F(AnsImageUtilUnitTest, CreatePixelMapByString_0200, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsImageUtilUnitTest, CreatePixelMapByString_0200, TestSize.Level1";
    MockImageSourceCreateImageSource(false, 0);
    MockImageSourceCreatePixelMap(true, 0);
    std::shared_ptr<AnsImageUtil> imageUtil = std::make_shared<AnsImageUtil>();
    ASSERT_NE(nullptr, imageUtil);
    std::string path = "123";
    std::shared_ptr<Media::PixelMap> res = imageUtil->CreatePixelMapByString(path);
    EXPECT_EQ(nullptr, res);
    MockResetImageSourceState();
}

/*
 * @tc.name: CreatePixelMapByString_0300
 * @tc.desc: test if AnsImageUtil's CreatePixelMapByString function.
 * @tc.type: FUNC
 * @tc.require: #I5SJ62
 */
HWTEST_F(AnsImageUtilUnitTest, CreatePixelMapByString_0300, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsImageUtilUnitTest, CreatePixelMapByString_0300, TestSize.Level1";
    MockImageSourceCreateImageSource(true, 1);
    MockImageSourceCreatePixelMap(true, 0);
    std::shared_ptr<AnsImageUtil> imageUtil = std::make_shared<AnsImageUtil>();
    ASSERT_NE(nullptr, imageUtil);
    std::string path = "123";
    std::shared_ptr<Media::PixelMap> res = imageUtil->CreatePixelMapByString(path);
    EXPECT_EQ(nullptr, res);
    MockResetImageSourceState();
}

/*
 * @tc.name: CreatePixelMapByString_0400
 * @tc.desc: test if AnsImageUtil's CreatePixelMapByString function.
 * @tc.type: FUNC
 * @tc.require: #I5SJ62
 */
HWTEST_F(AnsImageUtilUnitTest, CreatePixelMapByString_0400, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsImageUtilUnitTest, CreatePixelMapByString_0400, TestSize.Level1";
    MockImageSourceCreateImageSource(true, 0);
    MockImageSourceCreatePixelMap(false, 0);
    std::shared_ptr<AnsImageUtil> imageUtil = std::make_shared<AnsImageUtil>();
    ASSERT_NE(nullptr, imageUtil);
    std::string path = "123";
    std::shared_ptr<Media::PixelMap> res = imageUtil->CreatePixelMapByString(path);
    EXPECT_EQ(nullptr, res);
    MockResetImageSourceState();
}

/*
 * @tc.name: CreatePixelMapByString_0500
 * @tc.desc: test if AnsImageUtil's CreatePixelMapByString function.
 * @tc.type: FUNC
 * @tc.require: #I5SJ62
 */
HWTEST_F(AnsImageUtilUnitTest, CreatePixelMapByString_0500, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsImageUtilUnitTest, CreatePixelMapByString_0500, TestSize.Level1";
    MockImageSourceCreateImageSource(true, 0);
    MockImageSourceCreatePixelMap(true, 1);
    std::shared_ptr<AnsImageUtil> imageUtil = std::make_shared<AnsImageUtil>();
    ASSERT_NE(nullptr, imageUtil);
    std::string path = "123";
    std::shared_ptr<Media::PixelMap> res = imageUtil->CreatePixelMapByString(path);
    EXPECT_EQ(nullptr, res);
    MockResetImageSourceState();
}

/*
 * @tc.name: CreatePixelMapByString_0600
 * @tc.desc: test CreatePixelMapByString function.
 * @tc.type: FUNC
 * @tc.require: #I5SJ62
 */
HWTEST_F(AnsImageUtilUnitTest, CreatePixelMapByString_0600, Function | MediumTest | Level1)
{
    GTEST_LOG_(INFO)
        << "AnsImageUtilUnitTest, CreatePixelMapByString_0600, TestSize.Level1";
    MockImageSourceCreateImageSource(true, 0);
    MockImageSourceCreatePixelMap(true, 0);
    std::shared_ptr<AnsImageUtil> imageUtil = std::make_shared<AnsImageUtil>();
    ASSERT_NE(nullptr, imageUtil);
    std::string path = "123";
    std::shared_ptr<Media::PixelMap> res = imageUtil->CreatePixelMapByString(path);
    EXPECT_NE(nullptr, res);
    MockResetImageSourceState();
}
