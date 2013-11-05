/*
 * Copyright 2000-2013 JetBrains s.r.o.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package jetbrains.teamcilty.github.api.impl;

import jetbrains.buildServer.version.ServerVersionHolder;
import jetbrains.teamcilty.github.api.GitHubApi;
import jetbrains.teamcilty.github.api.GitHubApiFactory;
import jetbrains.teamcilty.github.api.GitHubConnectionParameters;
import org.eclipse.egit.github.core.client.GitHubClient;
import org.jetbrains.annotations.NotNull;

import java.net.URI;

/**
 * Created by Eugene Petrenko (eugene.petrenko@gmail.com)
 * Date: 06.09.12 2:54
 */
public class GitHubApiFactoryImpl implements GitHubApiFactory {
  private final HttpClientWrapper myWrapper;

  public GitHubApiFactoryImpl(@NotNull final HttpClientWrapper wrapper) {
    myWrapper = wrapper;
  }

  @NotNull
  public GitHubApi openGitHub(@NotNull final GitHubConnectionParameters parameters) {
    final URI uri = parameters.getURI();
    final GitHubClient client = ApacheHttpBasedGitHubClient.createClient(uri, myWrapper);
    client.setUserAgent("JetBrains TeamCity " + ServerVersionHolder.getVersion().getDisplayVersion());
    parameters.applyCredentials(client);
    return new GitHubApiImpl(client);
  }
}
