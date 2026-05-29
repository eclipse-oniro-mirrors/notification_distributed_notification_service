/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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
#include "picture_option.h"
#undef private
#undef protected

using namespace testing::ext;
namespace OHOS {
namespace Notification {
class PictureOptionTest : public testing::Test {
public:
    static void SetUpTestCase() {}
    static void TearDownTestCase() {}
    void SetUp() {}
    void TearDown() {}
};

/**
 * @tc.name: Constructor_00001
 * @tc.desc: Test copy constructor with empty list.
 * @tc.type: FUNC
 * @tc.require: issueI5WRQ2
 */
HWTEST_F(PictureOptionTest, Constructor_00001, Function | SmallTest | Level1)
{
    PictureOption option1;
    PictureOption option2(option1);
    EXPECT_EQ(option2.GetPreparseLiveViewPicList().size(), 0);
}

/**
 * @tc.name: Constructor_00002
 * @tc.desc: Test constructor with picList parameter.
 * @tc.type: FUNC
 * @tc.require: issueI5WRQ2
 */
HWTEST_F(PictureOptionTest, Constructor_00002, Function | SmallTest | Level1)
{
    std::vector<std::string> picList = {"pic1", "pic2", "pic3"};
    PictureOption option(picList);
    EXPECT_EQ(option.GetPreparseLiveViewPicList().size(), 3);
    EXPECT_EQ(option.GetPreparseLiveViewPicList()[0], "pic1");
}

/**
 * @tc.name: Constructor_00003
 * @tc.desc: Test copy constructor.
 * @tc.type: FUNC
 * @tc.require: issueI5WRQ2
 */
HWTEST_F(PictureOptionTest, Constructor_00003, Function | SmallTest | Level1)
{
    std::vector<std::string> picList = {"pic1", "pic2"};
    PictureOption option1(picList);
    PictureOption option2(option1);
    EXPECT_EQ(option2.GetPreparseLiveViewPicList().size(), 2);
    EXPECT_EQ(option2.GetPreparseLiveViewPicList()[0], "pic1");
}

/**
 * @tc.name: SetPreparseLiveViewPicList_00001
 * @tc.desc: Test SetPreparseLiveViewPicList.
 * @tc.type: FUNC
 * @tc.require: issueI5WRQ2
 */
HWTEST_F(PictureOptionTest, SetPreparseLiveViewPicList_00001, Function | SmallTest | Level1)
{
    PictureOption option;
    std::vector<std::string> picList = {"pic1"};
    option.SetPreparseLiveViewPicList(picList);
    EXPECT_EQ(option.GetPreparseLiveViewPicList().size(), 1);
    EXPECT_EQ(option.GetPreparseLiveViewPicList()[0], "pic1");
}

/**
 * @tc.name: SetPreparseLiveViewPicList_00002
 * @tc.desc: Test SetPreparseLiveViewPicList with empty list.
 * @tc.type: FUNC
 * @tc.require: issueI5WRQ2
 */
HWTEST_F(PictureOptionTest, SetPreparseLiveViewPicList_00002, Function | SmallTest | Level1)
{
    std::vector<std::string> picList = {"pic1"};
    PictureOption option(picList);
    option.SetPreparseLiveViewPicList({});
    EXPECT_EQ(option.GetPreparseLiveViewPicList().size(), 0);
}

/**
 * @tc.name: SetPreparseLiveViewPicList_00003
 * @tc.desc: Test SetPreparseLiveViewPicList multiple times.
 * @tc.type: FUNC
 * @tc.require: issueI5WRQ2
 */
HWTEST_F(PictureOptionTest, SetPreparseLiveViewPicList_00003, Function | SmallTest | Level1)
{
    PictureOption option;
    option.SetPreparseLiveViewPicList({"pic1"});
    option.SetPreparseLiveViewPicList({"pic2", "pic3"});
    option.SetPreparseLiveViewPicList({"pic4"});
    EXPECT_EQ(option.GetPreparseLiveViewPicList().size(), 1);
    EXPECT_EQ(option.GetPreparseLiveViewPicList()[0], "pic4");
}

/**
 * @tc.name: Marshalling_00001
 * @tc.desc: Test Marshalling with valid list.
 * @tc.type: FUNC
 * @tc.require: issueI5WRQ2
 */
HWTEST_F(PictureOptionTest, Marshalling_00001, Function | SmallTest | Level1)
{
    std::vector<std::string> picList = {"pic1", "pic2"};
    PictureOption option(picList);
    Parcel parcel;
    EXPECT_EQ(option.Marshalling(parcel), true);
}

/**
 * @tc.name: Marshalling_00002
 * @tc.desc: Test Marshalling with empty list.
 * @tc.type: FUNC
 * @tc.require: issueI5WRQ2
 */
HWTEST_F(PictureOptionTest, Marshalling_00002, Function | SmallTest | Level1)
{
    PictureOption option;
    Parcel parcel;
    EXPECT_EQ(option.Marshalling(parcel), true);
}

/**
 * @tc.name: Unmarshalling_00001
 * @tc.desc: Test Unmarshalling with valid list.
 * @tc.type: FUNC
 * @tc.require: issueI5WRQ2
 */
HWTEST_F(PictureOptionTest, Unmarshalling_00001, Function | SmallTest | Level1)
{
    std::vector<std::string> picList = {"pic1", "pic2"};
    PictureOption option(picList);
    Parcel parcel;
    option.Marshalling(parcel);
    parcel.RewindRead(0);
    PictureOption *result = PictureOption::Unmarshalling(parcel);
    ASSERT_NE(result, nullptr);
    EXPECT_EQ(result->GetPreparseLiveViewPicList().size(), 2);
    EXPECT_EQ(result->GetPreparseLiveViewPicList()[0], "pic1");
    delete result;
}

/**
 * @tc.name: Unmarshalling_00002
 * @tc.desc: Test Unmarshalling with empty list.
 * @tc.type: FUNC
 * @tc.require: issueI5WRQ2
 */
HWTEST_F(PictureOptionTest, Unmarshalling_00002, Function | SmallTest | Level1)
{
    PictureOption option;
    Parcel parcel;
    option.Marshalling(parcel);
    parcel.RewindRead(0);
    PictureOption *result = PictureOption::Unmarshalling(parcel);
    ASSERT_NE(result, nullptr);
    EXPECT_EQ(result->GetPreparseLiveViewPicList().size(), 0);
    delete result;
}

/**
 * @tc.name: CopyAssignment_00001
 * @tc.desc: Test copy assignment operator.
 * @tc.type: FUNC
 * @tc.require: issueI5WRQ2
 */
HWTEST_F(PictureOptionTest, CopyAssignment_00001, Function | SmallTest | Level1)
{
    std::vector<std::string> picList = {"pic1"};
    PictureOption option1(picList);
    PictureOption option2;
    option2 = option1;
    EXPECT_EQ(option2.GetPreparseLiveViewPicList().size(), 1);
    EXPECT_EQ(option2.GetPreparseLiveViewPicList()[0], "pic1");
}

/**
 * @tc.name: CopyAssignment_00002
 * @tc.desc: Test copy assignment operator with empty list.
 * @tc.type: FUNC
 * @tc.require: issueI5WRQ2
 */
HWTEST_F(PictureOptionTest, CopyAssignment_00002, Function | SmallTest | Level1)
{
    PictureOption option1;
    PictureOption option2({"pic1"});
    option2 = option1;
    EXPECT_EQ(option2.GetPreparseLiveViewPicList().size(), 0);
}

/**
 * @tc.name: SelfAssignment_00001
 * @tc.desc: Test self assignment.
 * @tc.type: FUNC
 * @tc.require: issueI5WRQ2
 */
HWTEST_F(PictureOptionTest, SelfAssignment_00001, Function | SmallTest | Level1)
{
    std::vector<std::string> picList = {"pic1"};
    PictureOption option(picList);
    PictureOption& ref = option;
    option = ref;
    EXPECT_EQ(option.GetPreparseLiveViewPicList().size(), 1);
    EXPECT_EQ(option.GetPreparseLiveViewPicList()[0], "pic1");
}

/**
 * @tc.name: Marshalling_Fail_00001
 * @tc.desc: Test Marshalling when WriteStringVector fails.
 * @tc.type: FUNC
 * @tc.require: issueI5WRQ2
 */
HWTEST_F(PictureOptionTest, Marshalling_Fail_00001, Function | SmallTest | Level1)
{
    PictureOption option({"pic1"});
    Parcel parcel;
    
#define private public
#include "parcel.h"
#undef private
    parcel.writable_ = false;
    
    bool result = option.Marshalling(parcel);
    EXPECT_EQ(result, false);
}

/**
 * @tc.name: LargeList_00001
 * @tc.desc: Test with large pic list.
 * @tc.type: FUNC
 * @tc.require: issueI5WRQ2
 */
HWTEST_F(PictureOptionTest, LargeList_00001, Function | SmallTest | Level1)
{
    std::vector<std::string> picList;
    for (int i = 0; i < 100; i++) {
        picList.push_back("pic" + std::to_string(i));
    }
    PictureOption option(picList);
    EXPECT_EQ(option.GetPreparseLiveViewPicList().size(), 100u);
    Parcel parcel;
    EXPECT_EQ(option.Marshalling(parcel), true);
    parcel.RewindRead(0);
    PictureOption* result = PictureOption::Unmarshalling(parcel);
    ASSERT_NE(result, nullptr);
    EXPECT_EQ(result->GetPreparseLiveViewPicList().size(), 100u);
    delete result;
}

/**
 * @tc.name: SpecialCharacters_00001
 * @tc.desc: Test with special characters in pic path.
 * @tc.type: FUNC
 * @tc.require: issueI5WRQ2
 */
HWTEST_F(PictureOptionTest, SpecialCharacters_00001, Function | SmallTest | Level1)
{
    std::vector<std::string> picList = {"path/to/pic.png", "pic_with_underscore.png", "pic-with-dash.png"};
    PictureOption option(picList);
    EXPECT_EQ(option.GetPreparseLiveViewPicList().size(), 3u);
    EXPECT_EQ(option.GetPreparseLiveViewPicList()[0], "path/to/pic.png");
    EXPECT_EQ(option.GetPreparseLiveViewPicList()[1], "pic_with_underscore.png");
    EXPECT_EQ(option.GetPreparseLiveViewPicList()[2], "pic-with-dash.png");
}

}  // namespace Notification
}  // namespace OHOS