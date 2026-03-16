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
#include "large_info_container.h"
#undef private
#undef protected
#include "message_parcel.h"

using namespace testing::ext;
namespace OHOS {
namespace Notification {
class LargeInfoContainerTest : public testing::Test {
public:
    static void SetUpTestCase() {}
    static void TearDownTestCase() {}
    void SetUp() {}
    void TearDown() {}
};

/**
 * @tc.name: Marshalling_0001
 * @tc.desc: Test LargeInfoContainer Marshalling success.
 * @tc.type: FUNC
 * @tc.require: issueI5W15B
 */
HWTEST_F(LargeInfoContainerTest, Marshalling_0001, Function | SmallTest | Level1)
{
    std::string value = "rawDataTest";
    for (int i = 0; i < 17; i++) {
        value = value + value;
    }
    sptr<RawDataContainer> rawDataContainer = new (std::nothrow) RawDataContainer(value);
    ASSERT_NE(rawDataContainer, nullptr);
    sptr<LargeInfoContainer> largeInfoContainer = new (std::nothrow) LargeInfoContainer(*rawDataContainer);
    ASSERT_NE(largeInfoContainer, nullptr);
    Parcel parcel;
    ASSERT_FALSE(largeInfoContainer->Marshalling(parcel));
    sptr<RawDataContainer> rawDataContainer2 = new (std::nothrow) RawDataContainer("rawDataTest");
    ASSERT_NE(rawDataContainer2, nullptr);
    largeInfoContainer->SetRawDataContainer(*rawDataContainer2);
    Parcel parcel2;
    ASSERT_TRUE(largeInfoContainer->Marshalling(parcel2));
    sptr<LargeInfoContainer> largeInfoContainer2 = largeInfoContainer->Unmarshalling(parcel2);
    ASSERT_NE(largeInfoContainer2, nullptr);
    EXPECT_EQ(largeInfoContainer2->GetRawDataContainer().GetRawString(), "rawDataTest");
}

/**
 * @tc.name: Unmarshalling_0001
 * @tc.desc: Test LargeInfoContainer Unmarshalling fail.
 * @tc.type: FUNC
 * @tc.require: issueI5W15B
 */
HWTEST_F(LargeInfoContainerTest, Unmarshalling_0001, Function | SmallTest | Level1)
{
    Parcel parcel;
    OHOS::MessageParcel &dataParcel = static_cast<OHOS::MessageParcel &>(parcel);
    ASSERT_TRUE(dataParcel.WriteUint32(static_cast<uint32_t>(NotificationConstant::MAX_IPC_RAW_DATA_SIZE + 1)));
    sptr<LargeInfoContainer> largeInfoContainer = new (std::nothrow) LargeInfoContainer();
    ASSERT_NE(largeInfoContainer, nullptr);
    sptr<LargeInfoContainer> largeInfoContainer2 = largeInfoContainer->Unmarshalling(parcel);
    EXPECT_EQ(largeInfoContainer2, nullptr);
}
}
}