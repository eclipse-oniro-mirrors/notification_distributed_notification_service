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
#include <memory>

#include "errors.h"
#include "nativetoken_kit.h"
#include "notification_want_params_helper.h"
#include "string_wrapper.h"
#include "token_setproc.h"
#include "want.h"
#include "want_agent_helper.h"
#include "want_params.h"
#include "want_params_wrapper.h"
#include "want_params_wrapper_json.h"

using namespace testing::ext;
namespace OHOS {
namespace Notification {
namespace {
constexpr int NESTING_DEPTH_OVER_LIMIT = 102;
}

class NotificationWantParamsHelperTest : public testing::Test {
public:
    static void SetUpTestCase()
    {
        NativeTokenInfoParams infoInstance = {
            .dcapsNum = 0,
            .permsNum = 0,
            .aclsNum = 0,
            .dcaps = nullptr,
            .perms = nullptr,
            .acls = nullptr,
            .aplStr = "system_basic",
        };
        infoInstance.processName = "ans_test";
        uint64_t tokenId = GetAccessTokenId(&infoInstance);
        SetSelfTokenID(tokenId);
    }
    static void TearDownTestCase() {}
    void SetUp() {}
    void TearDown() {}

    static std::shared_ptr<AbilityRuntime::WantAgent::WantAgent> CreateWantAgent()
    {
        AAFwk::Want want;
        want.SetBundle("com.ohos.launcher");
        want.SetParam("agentKey", std::string("agentValue"));
        std::vector<std::shared_ptr<AAFwk::Want>> wants;
        wants.push_back(std::make_shared<AAFwk::Want>(want));
        std::vector<AbilityRuntime::WantAgent::WantAgentConstant::Flags> flags;
        AbilityRuntime::WantAgent::WantAgentInfo paramsInfo(100,
            AbilityRuntime::WantAgent::WantAgentConstant::OperationType::START_ABILITY,
            flags, wants, nullptr);
        return AbilityRuntime::WantAgent::WantAgentHelper::GetWantAgent(paramsInfo);
    }
};

/**
 * @tc.name: SerializeWantParams_00001
 * @tc.desc: Serialize a WantParams with string param to envelope format.
 * @tc.type: FUNC
 */
HWTEST_F(NotificationWantParamsHelperTest, SerializeWantParams_00001, Function | SmallTest | Level1)
{
    AAFwk::WantParams params;
    params.SetParam("key1", AAFwk::String::Box("value1"));

    std::string out = NotificationWantParamsHelper::SerializeWantParams(params);

    EXPECT_FALSE(out.empty());
    EXPECT_NE(out.find(AAFwk::WantParamWrapperJson::ENVELOPE_KEY), std::string::npos);
}

/**
 * @tc.name: SerializeWantParams_00002
 * @tc.desc: Serialize an empty WantParams, the envelope string should not be empty.
 * @tc.type: FUNC
 */
HWTEST_F(NotificationWantParamsHelperTest, SerializeWantParams_00002, Function | SmallTest | Level1)
{
    AAFwk::WantParams params;

    std::string out = NotificationWantParamsHelper::SerializeWantParams(params);

    EXPECT_FALSE(out.empty());
    EXPECT_NE(out.find(AAFwk::WantParamWrapperJson::ENVELOPE_KEY), std::string::npos);
}

/**
 * @tc.name: SerializeWantParams_00003
 * @tc.desc: Serialize deeply nested WantParams, returns empty when depth exceeds limit.
 * @tc.type: FUNC
 */
HWTEST_F(NotificationWantParamsHelperTest, SerializeWantParams_00003, Function | SmallTest | Level1)
{
    AAFwk::WantParams deepWp;
    deepWp.SetParam("leaf", AAFwk::String::Box("leafValue"));
    for (int i = 0; i < NESTING_DEPTH_OVER_LIMIT; ++i) {
        AAFwk::WantParams outer;
        outer.SetParam("nested", AAFwk::WantParamWrapper::Box(deepWp));
        deepWp = outer;
    }

    std::string out = NotificationWantParamsHelper::SerializeWantParams(deepWp);

    EXPECT_TRUE(out.empty());
}

/**
 * @tc.name: ParseWantParams_00001
 * @tc.desc: Parse an empty string, should return empty WantParams.
 * @tc.type: FUNC
 */
HWTEST_F(NotificationWantParamsHelperTest, ParseWantParams_00001, Function | SmallTest | Level1)
{
    AAFwk::WantParams out = NotificationWantParamsHelper::ParseWantParams("");

    EXPECT_FALSE(out.HasParam("anyKey"));
}

/**
 * @tc.name: ParseWantParams_00002
 * @tc.desc: Parse an envelope-format string, round trip with SerializeWantParams.
 * @tc.type: FUNC
 */
HWTEST_F(NotificationWantParamsHelperTest, ParseWantParams_00002, Function | SmallTest | Level1)
{
    AAFwk::WantParams params;
    params.SetParam("key1", AAFwk::String::Box("value1"));
    std::string serialized = NotificationWantParamsHelper::SerializeWantParams(params);

    AAFwk::WantParams out = NotificationWantParamsHelper::ParseWantParams(serialized);

    EXPECT_TRUE(out.HasParam("key1"));
    EXPECT_EQ(out.GetStringParam("key1"), "value1");
}

/**
 * @tc.name: ParseWantParams_00003
 * @tc.desc: Parse a legacy-format string produced by WantParamWrapper::ToString.
 * @tc.type: FUNC
 */
HWTEST_F(NotificationWantParamsHelperTest, ParseWantParams_00003, Function | SmallTest | Level1)
{
    AAFwk::WantParams params;
    params.SetParam("key1", AAFwk::String::Box("value1"));
    AAFwk::WantParamWrapper wrapper(params);
    std::string legacy = wrapper.ToString();

    AAFwk::WantParams out = NotificationWantParamsHelper::ParseWantParams(legacy);

    EXPECT_TRUE(out.HasParam("key1"));
    EXPECT_EQ(out.GetStringParam("key1"), "value1");
}

/**
 * @tc.name: ParseWantParams_00004
 * @tc.desc: Parse malformed envelope (HasEnvelope true, Parse fails), returns empty.
 * @tc.type: FUNC
 */
HWTEST_F(NotificationWantParamsHelperTest, ParseWantParams_00004, Function | SmallTest | Level1)
{
    std::string malformed = std::string("{\"") + AAFwk::WantParamWrapperJson::ENVELOPE_KEY + "\":}";
    EXPECT_TRUE(AAFwk::WantParamWrapperJson::HasEnvelope(malformed));

    AAFwk::WantParams out = NotificationWantParamsHelper::ParseWantParams(malformed);

    EXPECT_FALSE(out.HasParam("anyKey"));
}

/**
 * @tc.name: ParseWantParamsWithBrackets_00001
 * @tc.desc: Parse an empty string with brackets variant, should return empty WantParams.
 * @tc.type: FUNC
 */
HWTEST_F(NotificationWantParamsHelperTest, ParseWantParamsWithBrackets_00001, Function | SmallTest | Level1)
{
    AAFwk::WantParams out = NotificationWantParamsHelper::ParseWantParamsWithBrackets("");

    EXPECT_FALSE(out.HasParam("anyKey"));
}

/**
 * @tc.name: ParseWantParamsWithBrackets_00002
 * @tc.desc: Parse an envelope-format string with brackets variant, round trip.
 * @tc.type: FUNC
 */
HWTEST_F(NotificationWantParamsHelperTest, ParseWantParamsWithBrackets_00002, Function | SmallTest | Level1)
{
    AAFwk::WantParams params;
    params.SetParam("key2", AAFwk::String::Box("value2"));
    std::string serialized = NotificationWantParamsHelper::SerializeWantParams(params);

    AAFwk::WantParams out = NotificationWantParamsHelper::ParseWantParamsWithBrackets(serialized);

    EXPECT_TRUE(out.HasParam("key2"));
    EXPECT_EQ(out.GetStringParam("key2"), "value2");
}

/**
 * @tc.name: ParseWantParamsWithBrackets_00003
 * @tc.desc: Parse a legacy-format string with brackets variant.
 * @tc.type: FUNC
 */
HWTEST_F(NotificationWantParamsHelperTest, ParseWantParamsWithBrackets_00003, Function | SmallTest | Level1)
{
    AAFwk::WantParams params;
    params.SetParam("key2", AAFwk::String::Box("value2"));
    AAFwk::WantParamWrapper wrapper(params);
    std::string legacy = wrapper.ToString();

    AAFwk::WantParams out = NotificationWantParamsHelper::ParseWantParamsWithBrackets(legacy);

    EXPECT_TRUE(out.HasParam("key2"));
    EXPECT_EQ(out.GetStringParam("key2"), "value2");
}

/**
 * @tc.name: ParseWantParamsWithBrackets_00004
 * @tc.desc: Parse malformed envelope with brackets variant, returns empty.
 * @tc.type: FUNC
 */
HWTEST_F(NotificationWantParamsHelperTest, ParseWantParamsWithBrackets_00004, Function | SmallTest | Level1)
{
    std::string malformed = std::string("{\"") + AAFwk::WantParamWrapperJson::ENVELOPE_KEY + "\":}";
    EXPECT_TRUE(AAFwk::WantParamWrapperJson::HasEnvelope(malformed));

    AAFwk::WantParams out = NotificationWantParamsHelper::ParseWantParamsWithBrackets(malformed);

    EXPECT_FALSE(out.HasParam("anyKey"));
}

/**
 * @tc.name: TryParseWantParams_00001
 * @tc.desc: Try to parse an envelope-format string, should succeed and fill the result.
 * @tc.type: FUNC
 */
HWTEST_F(NotificationWantParamsHelperTest, TryParseWantParams_00001, Function | SmallTest | Level1)
{
    AAFwk::WantParams params;
    params.SetParam("key1", AAFwk::String::Box("value1"));
    std::string serialized = NotificationWantParamsHelper::SerializeWantParams(params);

    AAFwk::WantParams out;
    EXPECT_TRUE(NotificationWantParamsHelper::TryParseWantParams(serialized, out));

    EXPECT_TRUE(out.HasParam("key1"));
    EXPECT_EQ(out.GetStringParam("key1"), "value1");
}

/**
 * @tc.name: TryParseWantParams_00002
 * @tc.desc: Try to parse an empty string, should succeed with an empty WantParams.
 * @tc.type: FUNC
 */
HWTEST_F(NotificationWantParamsHelperTest, TryParseWantParams_00002, Function | SmallTest | Level1)
{
    AAFwk::WantParams out;
    out.SetParam("stale", AAFwk::String::Box("staleValue"));

    EXPECT_TRUE(NotificationWantParamsHelper::TryParseWantParams("", out));

    EXPECT_FALSE(out.HasParam("stale"));
    EXPECT_FALSE(out.HasParam("anyKey"));
}

/**
 * @tc.name: TryParseWantParams_00003
 * @tc.desc: Try to parse a malformed envelope, should report failure and reset the result.
 * @tc.type: FUNC
 */
HWTEST_F(NotificationWantParamsHelperTest, TryParseWantParams_00003, Function | SmallTest | Level1)
{
    std::string malformed = std::string("{\"") + AAFwk::WantParamWrapperJson::ENVELOPE_KEY + "\":}";
    EXPECT_TRUE(AAFwk::WantParamWrapperJson::HasEnvelope(malformed));

    AAFwk::WantParams out;
    out.SetParam("stale", AAFwk::String::Box("staleValue"));

    EXPECT_FALSE(NotificationWantParamsHelper::TryParseWantParams(malformed, out));

    EXPECT_FALSE(out.HasParam("stale"));
    EXPECT_FALSE(out.HasParam("anyKey"));
}

/**
 * @tc.name: TryParseWantParams_00004
 * @tc.desc: Try to parse a valid envelope holding an empty WantParams, should succeed.
 * @tc.type: FUNC
 */
HWTEST_F(NotificationWantParamsHelperTest, TryParseWantParams_00004, Function | SmallTest | Level1)
{
    AAFwk::WantParams emptyParams;
    std::string serialized = NotificationWantParamsHelper::SerializeWantParams(emptyParams);
    ASSERT_FALSE(serialized.empty());

    AAFwk::WantParams out;
    EXPECT_TRUE(NotificationWantParamsHelper::TryParseWantParams(serialized, out));

    EXPECT_FALSE(out.HasParam("anyKey"));
}

/**
 * @tc.name: TryParseWantParams_00005
 * @tc.desc: Try to parse a legacy-format string, should keep the best-effort success semantics.
 * @tc.type: FUNC
 */
HWTEST_F(NotificationWantParamsHelperTest, TryParseWantParams_00005, Function | SmallTest | Level1)
{
    AAFwk::WantParams params;
    params.SetParam("key1", AAFwk::String::Box("value1"));
    AAFwk::WantParamWrapper wrapper(params);
    std::string legacy = wrapper.ToString();

    AAFwk::WantParams out;
    EXPECT_TRUE(NotificationWantParamsHelper::TryParseWantParams(legacy, out));

    EXPECT_TRUE(out.HasParam("key1"));
    EXPECT_EQ(out.GetStringParam("key1"), "value1");
}

/**
 * @tc.name: TryParseWantParamsWithBrackets_00001
 * @tc.desc: Try to parse with the brackets variant: envelope succeeds, malformed fails, legacy succeeds.
 * @tc.type: FUNC
 */
HWTEST_F(NotificationWantParamsHelperTest, TryParseWantParamsWithBrackets_00001, Function | SmallTest | Level1)
{
    AAFwk::WantParams params;
    params.SetParam("key2", AAFwk::String::Box("value2"));
    std::string serialized = NotificationWantParamsHelper::SerializeWantParams(params);
    AAFwk::WantParams out;
    EXPECT_TRUE(NotificationWantParamsHelper::TryParseWantParamsWithBrackets(serialized, out));
    EXPECT_EQ(out.GetStringParam("key2"), "value2");

    std::string malformed = std::string("{\"") + AAFwk::WantParamWrapperJson::ENVELOPE_KEY + "\":}";
    EXPECT_FALSE(NotificationWantParamsHelper::TryParseWantParamsWithBrackets(malformed, out));
    EXPECT_FALSE(out.HasParam("key2"));

    AAFwk::WantParamWrapper wrapper(params);
    EXPECT_TRUE(NotificationWantParamsHelper::TryParseWantParamsWithBrackets(wrapper.ToString(), out));
    EXPECT_EQ(out.GetStringParam("key2"), "value2");
}

/**
 * @tc.name: SerializeWantAgent_00001
 * @tc.desc: Serialize a null WantAgent, should return empty string.
 * @tc.type: FUNC
 */
HWTEST_F(NotificationWantParamsHelperTest, SerializeWantAgent_00001, Function | SmallTest | Level1)
{
    std::shared_ptr<AbilityRuntime::WantAgent::WantAgent> agent = nullptr;

    std::string out = NotificationWantParamsHelper::SerializeWantAgent(agent);

    EXPECT_TRUE(out.empty());
}

/**
 * @tc.name: SerializeWantAgent_00002
 * @tc.desc: Serialize a valid WantAgent, should return non-empty envelope string.
 * @tc.type: FUNC
 */
HWTEST_F(NotificationWantParamsHelperTest, SerializeWantAgent_00002, Function | SmallTest | Level1)
{
    auto agent = NotificationWantParamsHelperTest::CreateWantAgent();
    ASSERT_NE(agent, nullptr);

    std::string out = NotificationWantParamsHelper::SerializeWantAgent(agent);

    EXPECT_FALSE(out.empty());
    EXPECT_TRUE(AbilityRuntime::WantAgent::WantAgentHelper::HasWantParamsEnvelope(out));
    EXPECT_NE(out.find("com.ohos.launcher"), std::string::npos);
}

/**
 * @tc.name: ParseWantAgent_00001
 * @tc.desc: Parse an empty string, should return nullptr.
 * @tc.type: FUNC
 */
HWTEST_F(NotificationWantParamsHelperTest, ParseWantAgent_00001, Function | SmallTest | Level1)
{
    auto agent = NotificationWantParamsHelper::ParseWantAgent("");

    EXPECT_EQ(agent, nullptr);
}

/**
 * @tc.name: ParseWantAgent_00002
 * @tc.desc: Parse an envelope-format string, round trip with SerializeWantAgent.
 * @tc.type: FUNC
 */
HWTEST_F(NotificationWantParamsHelperTest, ParseWantAgent_00002, Function | SmallTest | Level1)
{
    auto agent = NotificationWantParamsHelperTest::CreateWantAgent();
    ASSERT_NE(agent, nullptr);
    std::string serialized = NotificationWantParamsHelper::SerializeWantAgent(agent);
    ASSERT_FALSE(serialized.empty());

    auto parsed = NotificationWantParamsHelper::ParseWantAgent(serialized);

    EXPECT_NE(parsed, nullptr);
    ASSERT_NE(parsed, nullptr);
    std::string bundleName;
    EXPECT_EQ(AbilityRuntime::WantAgent::WantAgentHelper::GetBundleName(parsed, bundleName), ERR_OK);
    EXPECT_EQ(bundleName, "com.ohos.launcher");
}

/**
 * @tc.name: ParseWantAgent_00003
 * @tc.desc: Parse a legacy-format string produced by WantAgentHelper::ToString.
 * @tc.type: FUNC
 */
HWTEST_F(NotificationWantParamsHelperTest, ParseWantAgent_00003, Function | SmallTest | Level1)
{
    auto agent = NotificationWantParamsHelperTest::CreateWantAgent();
    ASSERT_NE(agent, nullptr);
    std::string legacy = AbilityRuntime::WantAgent::WantAgentHelper::ToString(agent);
    ASSERT_FALSE(legacy.empty());

    auto parsed = NotificationWantParamsHelper::ParseWantAgent(legacy);

    EXPECT_NE(parsed, nullptr);
    ASSERT_NE(parsed, nullptr);
    std::string bundleName;
    EXPECT_EQ(AbilityRuntime::WantAgent::WantAgentHelper::GetBundleName(parsed, bundleName), ERR_OK);
    EXPECT_EQ(bundleName, "com.ohos.launcher");
}

/**
 * @tc.name: WantAgentEnvelopeSerializeGuardTest001
 * @tc.desc: Guard: production WantAgent serialization stays on the envelope interface (AC-3.1).
 * @tc.type: FUNC
 */
HWTEST_F(NotificationWantParamsHelperTest, WantAgentEnvelopeSerializeGuardTest001, Function | SmallTest | Level1)
{
    auto agent = NotificationWantParamsHelperTest::CreateWantAgent();
    ASSERT_NE(agent, nullptr);

    std::string out = NotificationWantParamsHelper::SerializeWantAgent(agent);

    EXPECT_FALSE(out.empty());
    EXPECT_TRUE(AbilityRuntime::WantAgent::WantAgentHelper::HasWantParamsEnvelope(out));
    std::string legacy = AbilityRuntime::WantAgent::WantAgentHelper::ToString(agent);
    EXPECT_NE(out, legacy);
}

/**
 * @tc.name: WantAgentEnvelopeParseGuardTest001
 * @tc.desc: Guard: envelope data parses via FromStringWithEnvelope, legacy data keeps FromString fallback (AC-3.2).
 * @tc.type: FUNC
 */
HWTEST_F(NotificationWantParamsHelperTest, WantAgentEnvelopeParseGuardTest001, Function | SmallTest | Level1)
{
    auto agent = NotificationWantParamsHelperTest::CreateWantAgent();
    ASSERT_NE(agent, nullptr);

    std::string envelope = NotificationWantParamsHelper::SerializeWantAgent(agent);
    ASSERT_FALSE(envelope.empty());
    ASSERT_TRUE(AbilityRuntime::WantAgent::WantAgentHelper::HasWantParamsEnvelope(envelope));
    auto envelopeParsed = NotificationWantParamsHelper::ParseWantAgent(envelope);
    EXPECT_NE(envelopeParsed, nullptr);

    std::string legacy = AbilityRuntime::WantAgent::WantAgentHelper::ToString(agent);
    ASSERT_FALSE(legacy.empty());
    EXPECT_FALSE(AbilityRuntime::WantAgent::WantAgentHelper::HasWantParamsEnvelope(legacy));
    auto legacyParsed = NotificationWantParamsHelper::ParseWantAgent(legacy);
    EXPECT_NE(legacyParsed, nullptr);
    ASSERT_NE(legacyParsed, nullptr);
    std::string bundleName;
    EXPECT_EQ(AbilityRuntime::WantAgent::WantAgentHelper::GetBundleName(legacyParsed, bundleName), ERR_OK);
    EXPECT_EQ(bundleName, "com.ohos.launcher");
}

}  // namespace Notification
}  // namespace OHOS
