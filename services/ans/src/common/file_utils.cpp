/*
 * Copyright (c) 2024-2024 Huawei Device Co., Ltd.
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

#include "file_utils.h"

#include <fstream>

#include "ans_log_wrapper.h"
#ifdef CONFIG_POLICY_ENABLE
#include "config_policy_utils.h"
#endif
#include "securec.h"

namespace OHOS {
namespace Notification {
bool FileUtils::GetJsonByFilePath(const char *filePath, std::vector<nlohmann::json> &roots)
{
    ANS_LOGD("Get json value by file path.");
    if (filePath == nullptr) {
        ANS_LOGE("GetJsonByFilePath fail as filePath is null.");
        return false;
    }
    bool ret = false;
    nlohmann::json localRoot;
#ifdef CONFIG_POLICY_ENABLE
    CfgFiles *cfgFiles = GetCfgFiles(filePath);
    if (cfgFiles == nullptr) {
        ANS_LOGE("Not found filePath:%{public}s.", filePath);
        return false;
    }

    for (int32_t i = 0; i <= MAX_CFG_POLICY_DIRS_CNT - 1; i++) {
        if (cfgFiles->paths[i] && *(cfgFiles->paths[i]) != '\0' && GetJsonFromFile(cfgFiles->paths[i], localRoot)) {
            ANS_LOGD("Notification config file path:%{public}s.", cfgFiles->paths[i]);
            roots.push_back(localRoot);
            ret = true;
        }
    }
    FreeCfgFiles(cfgFiles);
#else
    ANS_LOGD("Use default notification config file path:%{public}s.", filePath);
    ret = GetJsonFromFile(filePath, localRoot);
    if (ret) {
        roots.push_back(localRoot);
    }
#endif
    return ret;
}

bool FileUtils::GetJsonFromFile(const char *path, nlohmann::json &root)
{
    std::ifstream file(path);
    if (!file.good()) {
        EVENT_LOGE("Failed to open file %{public}s.", path);
        return false;
    }
    root = nlohmann::json::parse(file, nullptr, false);
    file.close();
    if (root.is_discarded() || !root.is_structured()) {
        EVENT_LOGE("Failed to parse json from file %{public}s.", path);
        return false;
    }
    if (root.is_null() || root.empty() || !root.is_object()) {
        ANS_LOGE("GetJsonFromFile fail as invalid root.");
        return false;
    }
    return true;
}
}  // namespace Notification
}  // namespace OHOS
