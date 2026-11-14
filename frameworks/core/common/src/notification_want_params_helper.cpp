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

#include "notification_want_params_helper.h"

#include "ans_log_wrapper.h"
#include "want_agent_helper.h"
#include "want_params_wrapper.h"
#include "want_params_wrapper_json.h"

namespace OHOS {
namespace Notification {
namespace {
using LegacyParseFunc = AAFwk::WantParams (*)(const std::string &);

bool TryParseWantParamsImpl(const std::string &text, LegacyParseFunc legacyFallback, AAFwk::WantParams &out)
{
    out = AAFwk::WantParams();
    if (text.empty()) {
        return true;
    }
    if (AAFwk::WantParamWrapperJson::HasEnvelope(text)) {
        if (!AAFwk::WantParamWrapperJson::Parse(text, out)) {
            ANS_LOGW("parse want params envelope failed, return empty result");
            out = AAFwk::WantParams();
            return false;
        }
        return true;
    }
    out = legacyFallback(text);
    return true;
}

AAFwk::WantParams ParseWantParamsImpl(const std::string &text, LegacyParseFunc legacyFallback)
{
    AAFwk::WantParams out;
    (void)TryParseWantParamsImpl(text, legacyFallback, out);
    return out;
}
}

std::string NotificationWantParamsHelper::SerializeWantParams(const AAFwk::WantParams &wp)
{
    std::string out;
    if (!AAFwk::WantParamWrapperJson::Serialize(wp, out)) {
        ANS_LOGW("serialize want params to envelope failed, fallback to legacy format");
        AAFwk::WantParamWrapper wrapper(wp);
        out = wrapper.ToString();
    }
    return out;
}

AAFwk::WantParams NotificationWantParamsHelper::ParseWantParams(const std::string &text)
{
    return ParseWantParamsImpl(text, AAFwk::WantParamWrapper::ParseWantParams);
}

AAFwk::WantParams NotificationWantParamsHelper::ParseWantParamsWithBrackets(const std::string &text)
{
    return ParseWantParamsImpl(text, AAFwk::WantParamWrapper::ParseWantParamsWithBrackets);
}

bool NotificationWantParamsHelper::TryParseWantParams(const std::string &text, AAFwk::WantParams &out)
{
    return TryParseWantParamsImpl(text, AAFwk::WantParamWrapper::ParseWantParams, out);
}

bool NotificationWantParamsHelper::TryParseWantParamsWithBrackets(const std::string &text, AAFwk::WantParams &out)
{
    return TryParseWantParamsImpl(text, AAFwk::WantParamWrapper::ParseWantParamsWithBrackets, out);
}

std::string NotificationWantParamsHelper::SerializeWantAgent(
    const std::shared_ptr<AbilityRuntime::WantAgent::WantAgent> &agent)
{
    if (agent == nullptr) {
        return "";
    }
    return AbilityRuntime::WantAgent::WantAgentHelper::ToStringWithEnvelope(agent);
}

std::shared_ptr<AbilityRuntime::WantAgent::WantAgent> NotificationWantParamsHelper::ParseWantAgent(
    const std::string &text, int32_t uid)
{
    if (text.empty()) {
        return nullptr;
    }
    if (AbilityRuntime::WantAgent::WantAgentHelper::HasWantParamsEnvelope(text)) {
        return AbilityRuntime::WantAgent::WantAgentHelper::FromStringWithEnvelope(text, uid);
    }
    return AbilityRuntime::WantAgent::WantAgentHelper::FromString(text, uid);
}
}  // namespace Notification
}  // namespace OHOS
