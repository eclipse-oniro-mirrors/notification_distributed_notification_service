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

#include <thread>
#include <functional>
#include "gtest/gtest.h"

#include "mock_account_manager.h"
#include "mock_bundle_manager.h"
#include "mock_bundle_service_connector.h"

#include "ibundle_manager_repository.h"
#include "bundle_manager_repository_impl.h"
#include "bundle_manager_adapter.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace Notification {
namespace Infra {
class BundleManagerRepositoryImplTest : public Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
protected:
    MockBundleServiceConnector* mockConnectorPtr_;
    MockAccountMgr* mockAccountPtr_;
    sptr<MockBundleMgr> mockBundleMgrPtr_;
    std::unique_ptr<IBundleManagerRepository> repository_;
};

void BundleManagerRepositoryImplTest::SetUpTestCase() {}

void BundleManagerRepositoryImplTest::TearDownTestCase() {}

void BundleManagerRepositoryImplTest::SetUp()
{
    GTEST_LOG_(INFO) << "SetUp start";
    auto mockConnectorPtr = std::make_unique<MockBundleServiceConnector>();
    auto mockAccountPtr = std::make_unique<MockAccountMgr>();
    mockBundleMgrPtr_ = new MockBundleMgr();

    mockConnectorPtr_ = mockConnectorPtr.get();
    mockAccountPtr_ = mockAccountPtr.get();

    EXPECT_CALL(*mockConnectorPtr_, GetBundleManager())
        .WillRepeatedly(Return(mockBundleMgrPtr_));

    repository_ = std::make_unique<BundleManagerRepositoryImpl>(
        std::move(mockConnectorPtr), std::move(mockAccountPtr));
    GTEST_LOG_(INFO) << "SetUp end";
}

void BundleManagerRepositoryImplTest::TearDown()
{
    repository_.reset();
    GTEST_LOG_(INFO) << "TearDown";
}

/**
 * @tc.number    : IsSystemAppTest_0001
 * @tc.name      : IsSystemAppTest_0001
 * @tc.desc      : Test  function
 */
HWTEST_F(BundleManagerRepositoryImplTest, IsSystemAppTest_0001, Function | MediumTest | Level1)
{
    EXPECT_CALL(*mockBundleMgrPtr_, CheckIsSystemAppByUid(_))
        .WillOnce(Return(true));
    bool res = repository_->IsSystemApp(100);
    EXPECT_EQ(res, true);
}

/**
 * @tc.number    : IsSystemAppTest_0002
 * @tc.name      : IsSystemAppTest_0002
 * @tc.desc      : Test  function
 */
HWTEST_F(BundleManagerRepositoryImplTest, IsSystemAppTest_0002, Function | MediumTest | Level1)
{
    EXPECT_CALL(*mockBundleMgrPtr_, CheckIsSystemAppByUid(_))
        .WillOnce(Return(false));
    bool res = repository_->IsSystemApp(100);
    EXPECT_EQ(res, false);
}

/**
 * @tc.number    : GetBundleNameByUid_0001
 * @tc.name      : GetBundleNameByUid_0001
 * @tc.desc      : Test  function
 */
HWTEST_F(BundleManagerRepositoryImplTest, GetBundleNameByUid_0001, Function | MediumTest | Level1)
{
    int32_t uid = 100;
    std::string name = "com.example.test";
    EXPECT_CALL(*mockBundleMgrPtr_, GetNameForUid(uid,_))
        .WillOnce(DoAll(SetArgReferee<1>((name)), Return((ERR_OK))));
    std::string bundleName = repository_->GetBundleNameByUid(uid);
    EXPECT_EQ(bundleName, name);
}

/**
 * @tc.number    : GetBundleNameByUid_0002
 * @tc.name      : GetBundleNameByUid_0002
 * @tc.desc      : Test  function
 */
HWTEST_F(BundleManagerRepositoryImplTest, GetBundleNameByUid_0002, Function | MediumTest | Level1)
{
    int32_t uid = 100;
    std::string name = "com.example.test";
    EXPECT_CALL(*mockBundleMgrPtr_, GetNameForUid(uid,_))
        .WillOnce(DoAll(SetArgReferee<1>((name)), Return((-1))));
    std::string bundleName = repository_->GetBundleNameByUid(uid);
    EXPECT_EQ(bundleName, "");
}

/**
 * @tc.number    : GetDefaultUidByBundleName_0001
 * @tc.name      : GetDefaultUidByBundleName_0001
 * @tc.desc      : Test  function
 */
HWTEST_F(BundleManagerRepositoryImplTest, GetDefaultUidByBundleName_0001, Function | MediumTest | Level1)
{
    std::string name = "com.example.test";
    int32_t userId = 100;
    int32_t uid = 101;
    EXPECT_CALL(*mockBundleMgrPtr_, GetUidByBundleName(name,userId))
        .WillOnce(Return(uid));
    int32_t outUid = repository_->GetDefaultUidByBundleName(name, userId);
    EXPECT_EQ(outUid, uid);
}

/**
 * @tc.number    : GetDefaultUidByBundleName_0002
 * @tc.name      : GetDefaultUidByBundleName_0002
 * @tc.desc      : Test  function
 */
HWTEST_F(BundleManagerRepositoryImplTest, GetDefaultUidByBundleName_0002, Function | MediumTest | Level1)
{
    std::string name = "com.example.test";
    int32_t userId = 100;
    int32_t appIndex = 100;
    int32_t uid = 101;
    EXPECT_CALL(*mockBundleMgrPtr_, GetUidByBundleName(name,userId, appIndex))
        .WillOnce(Return(uid));
    int32_t outUid = repository_->GetDefaultUidByBundleName(name, userId, appIndex);
    EXPECT_EQ(outUid, uid);
}

/**
 * @tc.number    : GetDefaultUidByBundleName_0003
 * @tc.name      : GetDefaultUidByBundleName_0003
 * @tc.desc      : Test  function
 */
HWTEST_F(BundleManagerRepositoryImplTest, GetDefaultUidByBundleName_0003, Function | MediumTest | Level1)
{
    std::string name = "com.example.test";
    int32_t userId = 100;
    int32_t uid = -1;
    EXPECT_CALL(*mockBundleMgrPtr_, GetUidByBundleName(name,userId))
        .WillOnce(Return(uid));
    int32_t outUid = repository_->GetDefaultUidByBundleName(name, userId);
    EXPECT_EQ(outUid, uid);
}

/**
 * @tc.number    : GetAppIndexByUid_0001
 * @tc.name      : GetAppIndexByUid_0001
 * @tc.desc      : Test  function
 */
HWTEST_F(BundleManagerRepositoryImplTest, GetAppIndexByUid_0001, Function | MediumTest | Level1)
{
    int32_t uid = 100;
    int32_t appIndex = 100;
    EXPECT_CALL(*mockBundleMgrPtr_, GetNameAndIndexForUid(uid,_,_))
        .WillOnce(DoAll(SetArgReferee<2>((appIndex)), Return((ERR_OK))));
    int32_t outAppIndex = repository_->GetAppIndexByUid(uid);
    EXPECT_EQ(outAppIndex, appIndex);
}

/**
 * @tc.number    : GetAppIndexByUid_0002
 * @tc.name      : GetAppIndexByUid_0002
 * @tc.desc      : Test  function
 */
HWTEST_F(BundleManagerRepositoryImplTest, GetAppIndexByUid_0002, Function | MediumTest | Level1)
{
    int32_t uid = 100;
    EXPECT_CALL(*mockBundleMgrPtr_, GetNameAndIndexForUid(uid,_,_))
        .WillOnce(Return(-1));
    int32_t outAppIndex = repository_->GetAppIndexByUid(uid);
    EXPECT_EQ(outAppIndex, 0);
}

/**
 * @tc.number    : GetBundleInfoByBundleName_0001
 * @tc.name      : GetBundleInfoByBundleName_0001
 * @tc.desc      : Test  function
 */
HWTEST_F(BundleManagerRepositoryImplTest, GetBundleInfoByBundleName_0001, Function | MediumTest | Level1)
{
    std::string name = "com.example.test";
    int32_t userId = 100;
    int32_t uid = 100;
    AppExecFwk::BundleInfo externalBundle;
    externalBundle.name = name;
    externalBundle.uid = uid;
    EXPECT_CALL(*mockBundleMgrPtr_, GetBundleInfo(name,AppExecFwk::BundleFlag::GET_BUNDLE_WITH_ABILITIES,_,userId))
        .WillOnce(DoAll(SetArgReferee<2>((externalBundle)), Return((true))));
    NotificationBundleManagerInfo bundle;
    bool ret = repository_->GetBundleInfoByBundleName(name, userId, bundle);
    EXPECT_EQ(bundle.bundleName, name);
    EXPECT_EQ(bundle.uid, uid);
    EXPECT_EQ(ret, true);
}

/**
 * @tc.number    : GetBundleInfoByBundleName_0002
 * @tc.name      : GetBundleInfoByBundleName_0002
 * @tc.desc      : Test  function
 */
HWTEST_F(BundleManagerRepositoryImplTest, GetBundleInfoByBundleName_0002, Function | MediumTest | Level1)
{
    std::string name = "com.example.test";
    int32_t userId = 100;
    int32_t uid = 100;
    AppExecFwk::BundleInfo externalBundleInfo;
    EXPECT_CALL(*mockBundleMgrPtr_, GetBundleInfo(name,AppExecFwk::BundleFlag::GET_BUNDLE_WITH_ABILITIES,_,userId))
        .WillOnce(DoAll(SetArgReferee<2>((externalBundleInfo)), Return((false))));
    NotificationBundleManagerInfo bundleInfo;
    bool ret = repository_->GetBundleInfoByBundleName(name, userId, bundleInfo);
    EXPECT_EQ(ret, false);
}

/**
 * @tc.number    : GetBundleInfo_0001
 * @tc.name      : GetBundleInfo_0001
 * @tc.desc      : Test  function
 */
HWTEST_F(BundleManagerRepositoryImplTest, GetBundleInfo_0001, Function | MediumTest | Level1)
{
    std::string name = "com.example.test";
    int32_t userId = 100;
    NotificationBundleManagerFlag flag = GET_BUNDLE_DEFAULT;

    EXPECT_CALL(*mockBundleMgrPtr_, GetBundleInfo(_,_,_,_))
        .WillOnce(Return((false)));
    NotificationBundleManagerInfo bundleInfo;
    bool ret = repository_->GetBundleInfo(name, flag, userId, bundleInfo);
    EXPECT_EQ(ret, false);
}

/**
 * @tc.number    : GetBundleInfo_0002
 * @tc.name      : GetBundleInfo_0002
 * @tc.desc      : Test  function
 */
HWTEST_F(BundleManagerRepositoryImplTest, GetBundleInfo_0002, Function | MediumTest | Level1)
{
    std::string name = "com.example.test";
    int32_t userId = 100;
    int32_t uid = 100;
    NotificationBundleManagerFlag flag = GET_BUNDLE_DEFAULT;
    AppExecFwk::BundleInfo externalBundleInfo;
    externalBundleInfo.name = name;
    externalBundleInfo.uid = uid;
    externalBundleInfo.applicationInfo.allowEnableNotification = true;
    externalBundleInfo.applicationInfo.isSystemApp = false;
    externalBundleInfo.applicationInfo.appIndex = 6;
    externalBundleInfo.applicationInfo.accessTokenId = 100;
    externalBundleInfo.applicationInfo.label = "test";
    externalBundleInfo.applicationInfo.bundleName = name;
    externalBundleInfo.applicationInfo.installSource = "test";
    AppExecFwk::AbilityInfo ability;
    ability.isStageBasedModel = true;
    externalBundleInfo.abilityInfos.push_back(ability);
    EXPECT_CALL(*mockBundleMgrPtr_, GetBundleInfo(_,_,_,_))
        .WillOnce(DoAll(SetArgReferee<2>((externalBundleInfo)), Return((true))));

    EXPECT_CALL(*mockAccountPtr_, GetOsAccountLocalIdFromUid(uid, _))
        .WillOnce(DoAll(SetArgReferee<1>(userId), Return(ERR_OK)));
    NotificationBundleManagerInfo bundleInfo;
    bool ret = repository_->GetBundleInfo(name, flag, userId, bundleInfo);
    EXPECT_EQ(bundleInfo.bundleName, name);
    EXPECT_EQ(bundleInfo.uid, uid);
    EXPECT_TRUE(bundleInfo.applicationInfo.allowEnableNotification);
    EXPECT_FALSE(bundleInfo.applicationInfo.isSystemApp);
    EXPECT_EQ(bundleInfo.applicationInfo.appIndex, 6);
    EXPECT_EQ(bundleInfo.applicationInfo.accessTokenId, 100);
    EXPECT_EQ(bundleInfo.applicationInfo.label, "test");
    EXPECT_EQ(bundleInfo.applicationInfo.bundleName, name);
    EXPECT_EQ(bundleInfo.applicationInfo.installSource, "test");
    EXPECT_TRUE(bundleInfo.isStageBasedModel);
    EXPECT_EQ(ret, true);
}

/**
 * @tc.number    : GetBundleInfos_0001
 * @tc.name      : GetBundleInfos_0001
 * @tc.desc      : Test  function
 */
HWTEST_F(BundleManagerRepositoryImplTest, GetBundleInfos_0001, Function | MediumTest | Level1)
{
    int32_t userId = 100;
    NotificationBundleManagerFlag flag = GET_BUNDLE_DEFAULT;

    EXPECT_CALL(*mockBundleMgrPtr_, GetBundleInfos(_,_,_))
        .WillOnce(Return((false)));
    vector<NotificationBundleManagerInfo> bundleInfos;
    bool ret = repository_->GetBundleInfos(flag, bundleInfos, userId);
    EXPECT_EQ(ret, false);
}

/**
 * @tc.number    : GetBundleInfos_0002
 * @tc.name      : GetBundleInfos_0002
 * @tc.desc      : Test  function
 */
HWTEST_F(BundleManagerRepositoryImplTest, GetBundleInfos_0002, Function | MediumTest | Level1)
{
    std::string name = "com.example.test";
    int32_t userId = 100;
    NotificationBundleManagerFlag flag = GET_BUNDLE_DEFAULT;
    vector<AppExecFwk::BundleInfo> externalBundleInfos;
    AppExecFwk::BundleInfo externalBundleInfo;
    externalBundleInfo.name = name;
    externalBundleInfo.uid = 100;
    externalBundleInfos.emplace_back(externalBundleInfo);
    EXPECT_CALL(*mockBundleMgrPtr_, GetBundleInfos(_,_,_))
        .WillOnce(DoAll(SetArgReferee<1>((externalBundleInfos)), Return((true))));
    vector<NotificationBundleManagerInfo> bundleInfos;
    bool ret = repository_->GetBundleInfos(flag, bundleInfos, userId);
    EXPECT_EQ(bundleInfos.size(), externalBundleInfos.size());
    EXPECT_EQ(ret, true);
}

/**
 * @tc.number    : GetBundleInfoV9_0001
 * @tc.name      : GetBundleInfoV9_0001
 * @tc.desc      : Test  function
 */
HWTEST_F(BundleManagerRepositoryImplTest, GetBundleInfoV9_0001, Function | MediumTest | Level1)
{
    std::string name = "com.example.test";
    int32_t userId = 100;
    int32_t flag = 0;

    EXPECT_CALL(*mockBundleMgrPtr_, GetBundleInfoV9(_,_,_,_))
        .WillOnce(Return((-1)));
    NotificationBundleManagerInfo bundleInfo;
    bool ret = repository_->GetBundleInfoV9(name, flag, bundleInfo, userId);
    EXPECT_EQ(ret, false);
}

/**
 * @tc.number    : GetBundleInfoV9_0002
 * @tc.name      : GetBundleInfoV9_0002
 * @tc.desc      : Test  function
 */
HWTEST_F(BundleManagerRepositoryImplTest, GetBundleInfoV9_0002, Function | MediumTest | Level1)
{
    std::string name = "com.example.test";
    int32_t userId = 100;
    int32_t flag = 0;

    AppExecFwk::BundleInfo externalBundleInfo;
    externalBundleInfo.name = name;
    externalBundleInfo.uid = 100;
    EXPECT_CALL(*mockBundleMgrPtr_, GetBundleInfoV9(_,_,_,_))
        .WillOnce(DoAll(SetArgReferee<2>((externalBundleInfo)), Return((ERR_OK))));
    NotificationBundleManagerInfo bundleInfo;
    bool ret = repository_->GetBundleInfoV9(name, flag, bundleInfo, userId);
    EXPECT_EQ(bundleInfo.bundleName, name);
    EXPECT_EQ(bundleInfo.uid, 100);
    EXPECT_EQ(ret, true);
}

/**
 * @tc.number    : GetCloneAppIndexes_0001
 * @tc.name      : GetCloneAppIndexes_0001
 * @tc.desc      : Test  function
 */
HWTEST_F(BundleManagerRepositoryImplTest, GetCloneAppIndexes_0001, Function | MediumTest | Level1)
{
    std::string name = "com.example.test";
    int32_t userId = 100;
    std::vector<int32_t> appIndexes;

    EXPECT_CALL(*mockBundleMgrPtr_, GetCloneAppIndexes(_,_,_))
        .WillOnce(Return((-1)));
    bool ret = repository_->GetCloneAppIndexes(name, appIndexes, userId);
    EXPECT_EQ(ret, false);
}

/**
 * @tc.number    : GetCloneAppIndexes_0002
 * @tc.name      : GetCloneAppIndexes_0002
 * @tc.desc      : Test  function
 */
HWTEST_F(BundleManagerRepositoryImplTest, GetCloneAppIndexes_0002, Function | MediumTest | Level1)
{
    std::string name = "com.example.test";
    int32_t userId = 100;
    std::vector<int32_t> appIndexes;
    std::vector<int32_t> appIndexe2;
    appIndexes.emplace_back(0);
    appIndexes.emplace_back(1);
    EXPECT_CALL(*mockBundleMgrPtr_, GetCloneAppIndexes(_,_,_))
        .WillOnce(DoAll(SetArgReferee<1>((appIndexes)), Return((ERR_OK))));
    bool ret = repository_->GetCloneAppIndexes(name, appIndexe2, userId);
    EXPECT_EQ(appIndexe2[0], 0);
    EXPECT_EQ(appIndexe2[1], 1);
    EXPECT_EQ(ret, true);
}

/**
 * @tc.number    : GetCloneBundleInfo_0001
 * @tc.name      : GetCloneBundleInfo_0001
 * @tc.desc      : Test  function
 */
HWTEST_F(BundleManagerRepositoryImplTest, GetCloneBundleInfo_0001, Function | MediumTest | Level1)
{
    std::string name = "com.example.test";
    int32_t userId = 100;
    int32_t flag = 0;
    int32_t appIndex = 0;

    EXPECT_CALL(*mockBundleMgrPtr_, GetCloneBundleInfo(_,_,_,_,_))
        .WillOnce(Return((-1)));
    NotificationBundleManagerInfo bundleInfo;
    bool ret = repository_->GetCloneBundleInfo(name, flag, appIndex, bundleInfo, userId);
    EXPECT_EQ(ret, false);
}

/**
 * @tc.number    : GetCloneBundleInfo_0002
 * @tc.name      : GetCloneBundleInfo_0002
 * @tc.desc      : Test  function
 */
HWTEST_F(BundleManagerRepositoryImplTest, GetCloneBundleInfo_0002, Function | MediumTest | Level1)
{
    std::string name = "com.example.test";
    int32_t userId = 100;
    int32_t flag = 0;
    int32_t appIndex = 0;

    AppExecFwk::BundleInfo externalBundleInfo;
    externalBundleInfo.name = name;
    externalBundleInfo.uid = 100;
    EXPECT_CALL(*mockBundleMgrPtr_, GetCloneBundleInfo(_,_,_,_,_))
        .WillOnce(DoAll(SetArgReferee<3>((externalBundleInfo)), Return((ERR_OK))));
    NotificationBundleManagerInfo bundleInfo;
    bool ret = repository_->GetCloneBundleInfo(name, flag, appIndex, bundleInfo, userId);
    EXPECT_EQ(bundleInfo.bundleName, name);
    EXPECT_EQ(bundleInfo.uid, 100);
    EXPECT_EQ(ret, true);
}

/**
 * @tc.number    : CheckCurrentUserIdApp_0001
 * @tc.name      : CheckCurrentUserIdApp_0001
 * @tc.desc      : Test  function
 */
HWTEST_F(BundleManagerRepositoryImplTest, CheckCurrentUserIdApp_0001, Function | MediumTest | Level1)
{
    std::string name = "com.example.test";
    int32_t userId = 100;
    int32_t uid = 100;

    EXPECT_CALL(*mockBundleMgrPtr_, GetBundleInfoV9(_,_,_,_))
        .WillOnce(DoAll(Return((-1))));
    bool ret = repository_->CheckCurrentUserIdApp(name, uid, userId);
    EXPECT_EQ(ret, false);
}

/**
 * @tc.number    : CheckCurrentUserIdApp_0002
 * @tc.name      : CheckCurrentUserIdApp_0002
 * @tc.desc      : Test  function
 */
HWTEST_F(BundleManagerRepositoryImplTest, CheckCurrentUserIdApp_0002, Function | MediumTest | Level1)
{
    std::string name = "com.example.test";
    int32_t userId = 100;
    int32_t uid = 100;

    AppExecFwk::BundleInfo externalBundleInfo;
    externalBundleInfo.name = name;
    externalBundleInfo.uid = 100;
    EXPECT_CALL(*mockBundleMgrPtr_, GetBundleInfoV9(_,_,_,_))
        .WillOnce(DoAll(SetArgReferee<2>((externalBundleInfo)), Return((ERR_OK))));
    bool ret = repository_->CheckCurrentUserIdApp(name, uid, userId);
    EXPECT_EQ(ret, true);
}

/**
 * @tc.number    : CheckCurrentUserIdApp_0003
 * @tc.name      : CheckCurrentUserIdApp_0003
 * @tc.desc      : Test  function
 */
HWTEST_F(BundleManagerRepositoryImplTest, CheckCurrentUserIdApp_0003, Function | MediumTest | Level1)
{
    std::string name = "com.example.test";
    int32_t userId = 100;
    int32_t uid = 100;

    AppExecFwk::BundleInfo externalBundleInfo;
    externalBundleInfo.name = name;
    externalBundleInfo.uid = 101;
    EXPECT_CALL(*mockBundleMgrPtr_, GetBundleInfoV9(_,_,_,_))
        .WillOnce(DoAll(SetArgReferee<2>((externalBundleInfo)), Return((ERR_OK))));
    bool ret = repository_->CheckCurrentUserIdApp(name, uid, userId);
    EXPECT_EQ(ret, false);
}

/**
 * @tc.number    : CheckApiCompatibility_0001
 * @tc.name      : CheckApiCompatibility_0001
 * @tc.desc      : Test  function
 */
HWTEST_F(BundleManagerRepositoryImplTest, CheckApiCompatibility_0001, Function | MediumTest | Level1)
{

    std::string name = "com.example.test";
    int32_t uid = 100;
    int32_t userId = 99;
    sptr<NotificationBundleOption> bundleOption(new NotificationBundleOption(name, uid));
    AppExecFwk::BundleInfo externalBundle;
    externalBundle.name = name;
    externalBundle.uid = uid;
    AppExecFwk::AbilityInfo ability;
    ability.isStageBasedModel = true;
    externalBundle.abilityInfos.push_back(ability);
    EXPECT_CALL(*mockBundleMgrPtr_, GetBundleInfo(_,_,_,_))
        .WillOnce(DoAll(SetArgReferee<2>((externalBundle)), Return((true))));

    EXPECT_CALL(*mockAccountPtr_, GetOsAccountLocalIdFromUid(uid, _))
        .WillOnce(DoAll(SetArgReferee<1>(userId), Return(ERR_OK)));
    bool ret = repository_->CheckApiCompatibility(bundleOption);

    EXPECT_EQ(ret, false);
}

/**
 * @tc.number    : CheckApiCompatibility_0002
 * @tc.name      : CheckApiCompatibility_0002
 * @tc.desc      : Test  function
 */
HWTEST_F(BundleManagerRepositoryImplTest, CheckApiCompatibility_0002, Function | MediumTest | Level1)
{

    std::string name = "com.example.test";
    int32_t uid = 100;
    int32_t userId = 99;
    sptr<NotificationBundleOption> bundleOption(new NotificationBundleOption(name, uid));
    AppExecFwk::BundleInfo externalBundle;
    externalBundle.name = name;
    externalBundle.uid = uid;
    AppExecFwk::AbilityInfo ability;
    ability.isStageBasedModel = false;
    externalBundle.abilityInfos.push_back(ability);
    EXPECT_CALL(*mockBundleMgrPtr_, GetBundleInfo(_,_,_,_))
        .WillOnce(DoAll(SetArgReferee<2>((externalBundle)), Return((true))));

    EXPECT_CALL(*mockAccountPtr_, GetOsAccountLocalIdFromUid(uid, _))
        .WillOnce(DoAll(SetArgReferee<1>(userId), Return(ERR_OK)));
    bool ret = repository_->CheckApiCompatibility(bundleOption);

    EXPECT_EQ(ret, true);
}

/**
 * @tc.number    : CheckApiCompatibility_0003
 * @tc.name      : CheckApiCompatibility_0003
 * @tc.desc      : Test  function
 */
HWTEST_F(BundleManagerRepositoryImplTest, CheckApiCompatibility_0003, Function | MediumTest | Level1)
{

    std::string name = "com.example.test";
    int32_t uid = 100;
    int32_t userId = 99;
    sptr<NotificationBundleOption> bundleOption(new NotificationBundleOption(name, uid));
    EXPECT_CALL(*mockBundleMgrPtr_, GetBundleInfo(_,_,_,_))
        .WillOnce(Return((false)));
    EXPECT_CALL(*mockAccountPtr_, GetOsAccountLocalIdFromUid(uid, _))
        .WillOnce(DoAll(SetArgReferee<1>(userId), Return(ERR_OK)));
    bool ret = repository_->CheckApiCompatibility(bundleOption);

    EXPECT_EQ(ret, false);
}

/**
 * @tc.number    : IsAncoApp_0001
 * @tc.name      : IsAncoApp_0001
 * @tc.desc      : Test  function
 */
HWTEST_F(BundleManagerRepositoryImplTest, IsAncoApp_0001, Function | MediumTest | Level1)
{

    std::string name = "com.example.test";
    int32_t uid = 100;
    int32_t userId = 99;
    AppExecFwk::BundleInfo externalBundle;
    externalBundle.name = name;
    externalBundle.uid = uid;
    externalBundle.applicationInfo.codePath = "1";
    EXPECT_CALL(*mockBundleMgrPtr_, GetBundleInfoV9(_,_,_,_))
        .WillOnce(DoAll(SetArgReferee<2>((externalBundle)), Return((ERR_OK))));

    EXPECT_CALL(*mockAccountPtr_, GetOsAccountLocalIdFromUid(uid, _))
        .WillOnce(DoAll(SetArgReferee<1>(userId), Return(ERR_OK)));
    bool ret = repository_->IsAncoApp(name, uid);

    EXPECT_EQ(ret, true);
}

/**
 * @tc.number    : IsAncoApp_0002
 * @tc.name      : IsAncoApp_0002
 * @tc.desc      : Test  function
 */
HWTEST_F(BundleManagerRepositoryImplTest, IsAncoApp_0002, Function | MediumTest | Level1)
{

    std::string name = "com.example.test";
    int32_t uid = 100;
    int32_t userId = 99;
    AppExecFwk::BundleInfo externalBundle;
    externalBundle.name = name;
    externalBundle.uid = uid;
    externalBundle.applicationInfo.codePath = "0";
    EXPECT_CALL(*mockBundleMgrPtr_, GetBundleInfoV9(_,_,_,_))
        .WillOnce(DoAll(SetArgReferee<2>((externalBundle)), Return((ERR_OK))));

    EXPECT_CALL(*mockAccountPtr_, GetOsAccountLocalIdFromUid(uid, _))
        .WillOnce(DoAll(SetArgReferee<1>(userId), Return(ERR_OK)));
    bool ret = repository_->IsAncoApp(name, uid);

    EXPECT_EQ(ret, false);
}

/**
 * @tc.number    : IsAncoApp_0003
 * @tc.name      : IsAncoApp_0003
 * @tc.desc      : Test  function
 */
HWTEST_F(BundleManagerRepositoryImplTest, IsAncoApp_0003, Function | MediumTest | Level1)
{

    std::string name = "com.example.test";
    int32_t uid = 100;
    int32_t userId = 99;
    EXPECT_CALL(*mockBundleMgrPtr_, GetBundleInfoV9(_,_,_,_))
        .WillOnce(Return((-1)));

    EXPECT_CALL(*mockAccountPtr_, GetOsAccountLocalIdFromUid(uid, _))
        .WillOnce(DoAll(SetArgReferee<1>(userId), Return(ERR_OK)));
    bool ret = repository_->IsAncoApp(name, uid);

    EXPECT_EQ(ret, false);
}

/**
 * @tc.number    : IsAtomicServiceByBundle_0001
 * @tc.name      : IsAtomicServiceByBundle_0001
 * @tc.desc      : Test  function
 */
HWTEST_F(BundleManagerRepositoryImplTest, IsAtomicServiceByBundle_0001, Function | MediumTest | Level1)
{

    std::string name = "com.example.test";
    int32_t userId = 100;
    AppExecFwk::BundleInfo externalBundle;
    externalBundle.applicationInfo.bundleType = AppExecFwk::BundleType::ATOMIC_SERVICE;
    EXPECT_CALL(*mockBundleMgrPtr_, GetBundleInfoV9(_,_,_,_))
        .WillOnce(DoAll(SetArgReferee<2>((externalBundle)), Return((ERR_OK))));
    bool ret = repository_->IsAtomicServiceByBundle(name, userId);

    EXPECT_EQ(ret, true);
}

/**
 * @tc.number    : IsAtomicServiceByBundle_0002
 * @tc.name      : IsAtomicServiceByBundle_0002
 * @tc.desc      : Test  function
 */
HWTEST_F(BundleManagerRepositoryImplTest, IsAtomicServiceByBundle_0002, Function | MediumTest | Level1)
{

    std::string name = "com.example.test";
    int32_t userId = 100;
    AppExecFwk::BundleInfo externalBundle;
    EXPECT_CALL(*mockBundleMgrPtr_, GetBundleInfoV9(_,_,_,_))
        .WillOnce(DoAll(SetArgReferee<2>((externalBundle)), Return((ERR_OK))));
    bool ret = repository_->IsAtomicServiceByBundle(name, userId);

    EXPECT_EQ(ret, false);
}

/**
 * @tc.number    : IsAtomicServiceByBundle_0003
 * @tc.name      : IsAtomicServiceByBundle_0003
 * @tc.desc      : Test  function
 */
HWTEST_F(BundleManagerRepositoryImplTest, IsAtomicServiceByBundle_0003, Function | MediumTest | Level1)
{

    std::string name = "com.example.test";
    int32_t userId = 100;
    EXPECT_CALL(*mockBundleMgrPtr_, GetBundleInfoV9(_,_,_,_))
        .WillOnce(Return((-1)));
    bool ret = repository_->IsAtomicServiceByBundle(name, userId);

    EXPECT_EQ(ret, false);
}
}  // Infra
}  // namespace Notification
}  // namespace OHOS
