/*
 * Copyright (c) 2024-2025 Huawei Device Co., Ltd.
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
#include <functional>
#include "gtest/gtest.h"
#define private public
#include "dialog_status_data.h"
#undef private
 
using namespace testing::ext;
namespace OHOS {
namespace Notification {
class DialogStatusDataTest : public ::testing::Test {
protected:
    void SetUp() override {}
    void TearDown() override {}
};
 
/**
 * @tc.name      : Marshalling_0100
 * @tc.desc      : Test Marshalling with valid parcel
 */
HWTEST_F(DialogStatusDataTest, Marshalling_0100, Function | MediumTest | Level1)
{
    DialogStatusData dialogStatusData(EnabledDialogStatus::ALLOW_CLICKED);
    Parcel parcel;
    bool result = dialogStatusData.Marshalling(parcel);
    EXPECT_TRUE(result);
}
 
/**
 * @tc.name      : Unmarshalling_0100
 * @tc.desc      : Test Unmarshalling
 */
HWTEST_F(DialogStatusDataTest, Unmarshalling_0100, Function | MediumTest | Level1)
{
    DialogStatusData dialogStatusData(EnabledDialogStatus::ALLOW_CLICKED);
    Parcel parcel;
    DialogStatusData* dialogStatusDataPtr = dialogStatusData.Unmarshalling(parcel);
    EXPECT_NE(dialogStatusDataPtr, nullptr);
}
}  // namespace Notification
}  // namespace OHOS