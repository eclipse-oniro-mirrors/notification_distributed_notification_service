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

#ifndef OHOS_DISTRIBUTED_NOTIFICATION_SERVER_STS_CONVERT_OTHER_H
#define OHOS_DISTRIBUTED_NOTIFICATION_SERVER_STS_CONVERT_OTHER_H
#include "ani.h"
#include "resource_manager.h"
#include "pixel_map.h"
#include "want_agent.h"
#include "ani_common_want_agent.h"

using ResourceManager = OHOS::Global::Resource::ResourceManager;
namespace OHOS {
namespace NotificationSts {
using namespace OHOS::Media;
using namespace OHOS::AbilityRuntime::WantAgent;

void UnwrapWantAgent(ani_env *env, ani_object agent, void** result);
ani_object WarpWantAgent(ani_env *env, std::shared_ptr<WantAgent> wantAgent);
ani_object GetAniWantAgentArray(ani_env *env, std::vector<std::shared_ptr<WantAgent>> wantAgents);

ani_object CreateAniPixelMap(ani_env* env, std::shared_ptr<PixelMap> pixelMap);
std::shared_ptr<PixelMap> GetPixelMapFromEnvSp(ani_env* env, ani_object obj);
// ani_object to vector
ani_status GetPixelMapArrayByRef(ani_env *env, ani_ref param, std::vector<std::shared_ptr<PixelMap>> &pixelMaps);
// ani_object to vector
ani_status GetPixelMapArray(ani_env *env,
    ani_object param, const char *name, std::vector<std::shared_ptr<PixelMap>> &pixelMaps);
// map ro AniRecord
bool GetAniPictrueInfo(ani_env *env, std::map<std::string, std::vector<std::shared_ptr<Media::PixelMap>>> pictureMap,
    ani_object &pictureInfoObj);
// AniRecord to map
ani_status GetMapOfPictureInfo(ani_env *env, ani_object obj,
    std::map<std::string, std::vector<std::shared_ptr<Media::PixelMap>>> pictureMap);
// vector to AniArray
ani_object GetAniArrayPixelMap(ani_env *env, const std::vector<std::shared_ptr<Media::PixelMap>> &pixelMaps);

ani_status UnwrapResource(ani_env *env, ani_object obj, ResourceManager::Resource resource);
ani_status GetResourceArray(ani_env *env, ani_object param, const char *name, std::vector<ResourceManager::Resource> &res);
ani_object GetAniResource(ani_env *env, const std::shared_ptr<ResourceManager::Resource> &resource);
ani_object GetAniArrayResource(ani_env *env,
    const std::vector<std::shared_ptr<ResourceManager::Resource>> &resources);
} // namespace NotificationSts
} // OHOS
#endif