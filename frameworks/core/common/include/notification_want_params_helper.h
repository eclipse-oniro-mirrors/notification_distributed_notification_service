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

#ifndef BASE_NOTIFICATION_ANS_STANDARD_CORE_COMMON_NOTIFICATION_WANT_PARAMS_HELPER_H
#define BASE_NOTIFICATION_ANS_STANDARD_CORE_COMMON_NOTIFICATION_WANT_PARAMS_HELPER_H

#include <memory>
#include <string>

#include "want_params.h"

namespace OHOS {
namespace AbilityRuntime::WantAgent {
class WantAgent;
}

namespace Notification {
class NotificationWantParamsHelper {
public:
    /**
     * @brief Serialize WantParams to the envelope-based JSON wrapper format.
     *
     * This is the upgrade path for the legacy WantParamWrapper::ToString format.
     * New data should always be written through this API so that keys, typeId
     * strings, scalar values, backslashes, quotes and nested WantParams
     * delimiters are represented through JSON escaping.
     *
     * @param wp Indicates the WantParams to serialize.
     * @return Returns the serialized envelope string; returns an empty string
     * if serialization fails.
     */
    static std::string SerializeWantParams(const AAFwk::WantParams &wp);

    /**
     * @brief Parse a WantParams string with envelope detection.
     *
     * If the input carries the WantParamWrapperJson envelope, it is parsed by
     * the new strict JSON parser. Otherwise the legacy WantParamWrapper::Parse
     * path is used so that historical data round-trips unchanged.
     *
     * @param text Indicates the string to parse.
     * @return Returns the parsed WantParams; returns an empty WantParams when
     * the input is empty or parsing fails.
     */
    static AAFwk::WantParams ParseWantParams(const std::string &text);

    /**
     * @brief Parse a WantParams string with envelope detection, keeping the
     * legacy WithBrackets fallback for historical data.
     *
     * This mirrors ParseWantParams but the legacy branch uses
     * WantParamWrapper::ParseWantParamsWithBrackets so that callers that
     * historically relied on the bracket-tolerant parser keep their original
     * behavior for old data.
     *
     * @param text Indicates the string to parse.
     * @return Returns the parsed WantParams; returns an empty WantParams when
     * the input is empty or parsing fails.
     */
    static AAFwk::WantParams ParseWantParamsWithBrackets(const std::string &text);

    /**
     * @brief Parse WantParams and report whether a non-empty envelope is valid.
     * Empty and legacy inputs retain the existing compatible behavior.
     *
     * @param text Indicates the string to parse.
     * @param out Indicates the parsed WantParams, reset when parsing fails.
     * @return Returns false only when a non-empty envelope cannot be parsed.
     */
    static bool TryParseWantParams(const std::string &text, AAFwk::WantParams &out);

    /**
     * @brief Parse WantParams with the legacy WithBrackets fallback and report envelope failures.
     * Empty and legacy inputs retain the existing compatible behavior.
     *
     * @param text Indicates the string to parse.
     * @param out Indicates the parsed WantParams, reset when parsing fails.
     * @return Returns false only when a non-empty envelope cannot be parsed.
     */
    static bool TryParseWantParamsWithBrackets(const std::string &text, AAFwk::WantParams &out);

    /**
     * @brief Serialize a WantAgent to the envelope-based string format.
     *
     * This is the upgrade path for the legacy WantAgentHelper::ToString. The
     * extraInfo payload is emitted through WantParamWrapperJson::Serialize.
     *
     * @param agent Indicates the WantAgent to serialize.
     * @return Returns the serialized string; returns an empty string if the
     * agent is null or serialization fails.
     */
    static std::string SerializeWantAgent(const std::shared_ptr<AbilityRuntime::WantAgent::WantAgent> &agent);

    /**
     * @brief Parse a WantAgent string with envelope detection.
     *
     * If the input carries the WantParams envelope in extraInfo, it is parsed
     * by WantAgentHelper::FromStringWithEnvelope. Otherwise the legacy
     * WantAgentHelper::FromString is used so that historical data round-trips
     * unchanged.
     *
     * @param text Indicates the string to parse.
     * @param uid Indicates the target uid passed to the underlying parser.
     * @return Returns the parsed WantAgent; returns nullptr when the input is
     * empty or parsing fails.
     */
    static std::shared_ptr<AbilityRuntime::WantAgent::WantAgent> ParseWantAgent(
        const std::string &text, int32_t uid = -1);
};
}  // namespace Notification
}  // namespace OHOS

#endif  // BASE_NOTIFICATION_ANS_STANDARD_CORE_COMMON_NOTIFICATION_WANT_PARAMS_HELPER_H
