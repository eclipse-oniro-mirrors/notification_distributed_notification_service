/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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
#include "distributed_liveview_all_scenarios_extension_wrapper.h"
#undef private
#undef protected
 
using namespace testing::ext;
namespace OHOS {
namespace Notification {
class DistributedLiveviewAllScenariosExtensionWrapperTest : public testing::Test {
public:
    static void SetUpTestCase() {}
    static void TearDownTestCase() {}
    void SetUp() {}
    void TearDown() {}
};
 
/**
 * @tc.name: CloseExtentionWrapper_0100
 * @tc.desc: Test CloseExtentionWrapper.
 * @tc.type: FUNC
 */
HWTEST_F(DistributedLiveviewAllScenariosExtensionWrapperTest, CloseExtentionWrapper_0100, Function | SmallTest | Level1)
{
    DISTRIBUTED_LIVEVIEW_ALL_SCENARIOS_EXTENTION_WRAPPER->InitExtentionWrapper();
    EXPECT_NE(DISTRIBUTED_LIVEVIEW_ALL_SCENARIOS_EXTENTION_WRAPPER->updateLiveviewPiexlMap2BinFile_, nullptr);
    DISTRIBUTED_LIVEVIEW_ALL_SCENARIOS_EXTENTION_WRAPPER->CloseExtentionWrapper();
    EXPECT_EQ(DISTRIBUTED_LIVEVIEW_ALL_SCENARIOS_EXTENTION_WRAPPER->updateLiveviewPiexlMap2BinFile_, nullptr);
}
 
/**
 * @tc.name: DistributedLiveViewOperation_0100
 * @tc.desc: Test DistributedLiveViewOperation when distributedLiveViewOperation_ nullptr.
 * @tc.type: FUNC
 */
HWTEST_F(DistributedLiveviewAllScenariosExtensionWrapperTest,
    DistributedLiveViewOperation_0100, Function | SmallTest | Level1)
{
    sptr<NotificationRequest> request = new NotificationRequest(1);
    ErrCode res =
        DISTRIBUTED_LIVEVIEW_ALL_SCENARIOS_EXTENTION_WRAPPER->DistributedLiveViewOperation(request, 0, 0);
    EXPECT_EQ(res, ERR_OK);
}
 
/**
 * @tc.name: RestoreCollaborationWindow_0100
 * @tc.desc: Test RestoreCollaborationWindow when restoreCollaborationWindow_ nullptr.
 * @tc.type: FUNC
 */
HWTEST_F(DistributedLiveviewAllScenariosExtensionWrapperTest,
    RestoreCollaborationWindow_0100, Function | SmallTest | Level1)
{
    ErrCode res =
        DISTRIBUTED_LIVEVIEW_ALL_SCENARIOS_EXTENTION_WRAPPER->RestoreCollaborationWindow("");
    EXPECT_EQ(res, ERR_OK);
}
 
 
/**
 * @tc.name: DistributedAncoNotificationClick_0100
 * @tc.desc: Test DistributedAncoNotificationClick when distributedAncoNotificationClick_ nullptr.
 * @tc.type: FUNC
 */
HWTEST_F(DistributedLiveviewAllScenariosExtensionWrapperTest,
    DistributedAncoNotificationClick_0100, Function | SmallTest | Level1)
{
    bool triggerWantInner;
    ErrCode res = DISTRIBUTED_LIVEVIEW_ALL_SCENARIOS_EXTENTION_WRAPPER->DistributedAncoNotificationClick(
        nullptr, triggerWantInner);
    EXPECT_EQ(res, ERR_OK);
}
 
/**
 * @tc.name: UpdateLiveviewBinFile2PiexlMap_0100
 * @tc.desc: Test UpdateLiveviewBinFile2PiexlMap when updateLiveviewBinFile2PiexlMap_ nullptr.
 * @tc.type: FUNC
 */
HWTEST_F(DistributedLiveviewAllScenariosExtensionWrapperTest,
    UpdateLiveviewBinFile2PiexlMap_0100, Function | SmallTest | Level1)
{
    std::vector<uint8_t> buffer;
    std::shared_ptr<Media::PixelMap> pixelMap = nullptr;
    ErrCode res = DISTRIBUTED_LIVEVIEW_ALL_SCENARIOS_EXTENTION_WRAPPER->UpdateLiveviewBinFile2PiexlMap(
        pixelMap, buffer);
    EXPECT_EQ(res, ERR_OK);
    EXPECT_EQ(nullptr, pixelMap);
}
 
/**
 * @tc.name: UpdateLiveviewPiexlMap2BinFile_0100
 * @tc.desc: Test UpdateLiveviewPiexlMap2BinFile when updateLiveviewPiexlMap2BinFile_ nullptr.
 * @tc.type: FUNC
 */
HWTEST_F(DistributedLiveviewAllScenariosExtensionWrapperTest,
    UpdateLiveviewPiexlMap2BinFile_0100, Function | SmallTest | Level1)
{
    std::vector<uint8_t> buffer;
    ErrCode res = DISTRIBUTED_LIVEVIEW_ALL_SCENARIOS_EXTENTION_WRAPPER->UpdateLiveviewPiexlMap2BinFile(
        nullptr, buffer);
    EXPECT_EQ(res, ERR_OK);
    EXPECT_EQ(0, buffer.size());
}
 
/**
 * @tc.name: DistributedLiveViewOperation_0200
 * @tc.desc: Test DistributedLiveViewOperation success.
 * @tc.type: FUNC
 */
HWTEST_F(DistributedLiveviewAllScenariosExtensionWrapperTest,
    DistributedLiveViewOperation_0200, Function | SmallTest | Level1)
{
    DISTRIBUTED_LIVEVIEW_ALL_SCENARIOS_EXTENTION_WRAPPER->InitExtentionWrapper();
    ASSERT_NE(DISTRIBUTED_LIVEVIEW_ALL_SCENARIOS_EXTENTION_WRAPPER->updateLiveviewPiexlMap2BinFile_, nullptr);
    sptr<NotificationRequest> request = new NotificationRequest(1);
    ErrCode res =
        DISTRIBUTED_LIVEVIEW_ALL_SCENARIOS_EXTENTION_WRAPPER->DistributedLiveViewOperation(request, 34, 0);
    EXPECT_EQ(res, ERR_OK);
}
 
/**
 * @tc.name: RestoreCollaborationWindow_0200
 * @tc.desc: Test RestoreCollaborationWindow with invalid param.
 * @tc.type: FUNC
 */
HWTEST_F(DistributedLiveviewAllScenariosExtensionWrapperTest,
    RestoreCollaborationWindow_0200, Function | SmallTest | Level1)
{
    ErrCode res =
        DISTRIBUTED_LIVEVIEW_ALL_SCENARIOS_EXTENTION_WRAPPER->RestoreCollaborationWindow("");
    EXPECT_NE(res, ERR_OK);
}
 
/**
 * @tc.name: DistributedAncoNotificationClick_0200
 * @tc.desc: Test DistributedAncoNotificationClick with invalid param.
 * @tc.type: FUNC
 */
HWTEST_F(DistributedLiveviewAllScenariosExtensionWrapperTest,
    DistributedAncoNotificationClick_0200, Function | SmallTest | Level1)
{
    bool triggerWantInner;
    ErrCode res = DISTRIBUTED_LIVEVIEW_ALL_SCENARIOS_EXTENTION_WRAPPER->DistributedAncoNotificationClick(
        nullptr, triggerWantInner);
    EXPECT_EQ(res, -1);
}
 
/**
 * @tc.name: UpdateLiveviewBinFile2PiexlMap_0200
 * @tc.desc: Test UpdateLiveviewBinFile2PiexlMap with invalid param.
 * @tc.type: FUNC
 */
HWTEST_F(DistributedLiveviewAllScenariosExtensionWrapperTest,
    UpdateLiveviewBinFile2PiexlMap_0200, Function | SmallTest | Level1)
{
    std::vector<uint8_t> buffer;
    std::shared_ptr<Media::PixelMap> pixelMap = nullptr;
    ErrCode res = DISTRIBUTED_LIVEVIEW_ALL_SCENARIOS_EXTENTION_WRAPPER->UpdateLiveviewBinFile2PiexlMap(
        pixelMap, buffer);
    EXPECT_EQ(res, -1);
    EXPECT_EQ(nullptr, pixelMap);
}
 
/**
 * @tc.name: UpdateLiveviewPiexlMap2BinFile_0200
 * @tc.desc: Test UpdateLiveviewPiexlMap2BinFile with invalid param.
 * @tc.type: FUNC
 */
HWTEST_F(DistributedLiveviewAllScenariosExtensionWrapperTest,
    UpdateLiveviewPiexlMap2BinFile_0200, Function | SmallTest | Level1)
{
    std::vector<uint8_t> buffer;
    ErrCode res = DISTRIBUTED_LIVEVIEW_ALL_SCENARIOS_EXTENTION_WRAPPER->UpdateLiveviewPiexlMap2BinFile(
        nullptr, buffer);
    EXPECT_EQ(res, -1);
    EXPECT_EQ(0, buffer.size());
}
}
}