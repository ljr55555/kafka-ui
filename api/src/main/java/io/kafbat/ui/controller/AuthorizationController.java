package io.kafbat.ui.controller;

import io.kafbat.ui.api.AuthorizationApi;
import io.kafbat.ui.config.auth.AuthenticatedUser;
import io.kafbat.ui.model.ActionDTO;
import io.kafbat.ui.model.AuthenticationInfoDTO;
import io.kafbat.ui.model.KafkaCluster;
import io.kafbat.ui.model.ResourceTypeDTO;
import io.kafbat.ui.model.UserInfoDTO;
import io.kafbat.ui.model.UserPermissionDTO;
import io.kafbat.ui.model.rbac.Permission;
import io.kafbat.ui.model.rbac.Role;
import io.kafbat.ui.service.ClustersStorage;
import io.kafbat.ui.service.rbac.AccessControlService;
import java.security.Principal;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import javax.annotation.Nullable;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.oauth2.core.OAuth2AuthenticatedPrincipal;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

@RestController
@RequiredArgsConstructor
@Slf4j
public class AuthorizationController implements AuthorizationApi {

  private final AccessControlService accessControlService;
  private final ClustersStorage clustersStorage;

  public Mono<ResponseEntity<AuthenticationInfoDTO>> getUserAuthInfo(ServerWebExchange exchange) {
    List<UserPermissionDTO> defaultRolePermissions = accessControlService.getDefaultRole() != null
        ? mapPermissions(
            accessControlService.getDefaultRole().getPermissions(),
            clustersStorage.getKafkaClusters().stream().map(KafkaCluster::getName).toList())
        : Collections.emptyList();

    Mono<List<UserPermissionDTO>> permissions = AccessControlService.getUser()
        .map(user -> accessControlService.getRoles()
            .stream()
            .filter(role -> matchesRole(user, role))
            .map(role -> mapPermissions(role.getPermissions(), role.getClusters()))
            .flatMap(Collection::stream)
            .toList()
        )
        .map(userPermissions -> userPermissions.isEmpty() ? defaultRolePermissions : userPermissions)
        .switchIfEmpty(Mono.just(Collections.emptyList()));

    Mono<String> userName = ReactiveSecurityContextHolder.getContext()
        .map(SecurityContext::getAuthentication)
        .flatMap(auth -> Mono.justOrEmpty(resolvePrincipalName(auth)))
        .switchIfEmpty(Mono.just("authenticated"));

    var builder = new AuthenticationInfoDTO()
        .rbacEnabled(accessControlService.isRbacEnabled());

    return userName
        .zipWith(permissions)
        .map(data -> (AuthenticationInfoDTO) builder
            .userInfo(new UserInfoDTO(data.getT1(), data.getT2()))
        )
        .switchIfEmpty(Mono.just(builder))
        .map(ResponseEntity::ok);
  }

  private boolean matchesRole(AuthenticatedUser user, Role role) {
    return user.groups().contains(role.getName())
        || role.getName().equalsIgnoreCase(user.principal());
  }

  @Nullable
  private String resolvePrincipalName(@Nullable Authentication authentication) {
    if (authentication == null) {
      return null;
    }

    String name = authentication.getName();
    if (name != null && !name.isBlank()) {
      return name;
    }

    Object principal = authentication.getPrincipal();
    if (principal instanceof OAuth2AuthenticatedPrincipal oauth2Principal) {
      Map<String, Object> attributes = oauth2Principal.getAttributes();

      Object clientId = attributes.get("client_id");
      if (clientId != null) {
        return clientId.toString();
      }

      Object sub = attributes.get("sub");
      if (sub != null) {
        return sub.toString();
      }

      Object username = attributes.get("username");
      if (username != null) {
        return username.toString();
      }
    }

    if (principal instanceof Principal principalObj) {
      String principalName = principalObj.getName();
      if (principalName != null && !principalName.isBlank()) {
        return principalName;
      }
    }

    return null;
  }

  private List<UserPermissionDTO> mapPermissions(List<Permission> permissions, List<String> clusters) {
    return permissions
        .stream()
        .map(permission -> new UserPermissionDTO()
            .clusters(clusters)
            .resource(ResourceTypeDTO.fromValue(permission.getResource().toString().toUpperCase()))
            .value(permission.getValue())
            .actions(permission.getParsedActions()
                .stream()
                .map(p -> p.name().toUpperCase())
                .map(this::mapAction)
                .filter(Objects::nonNull)
                .toList())
        )
        .toList();
  }

  @Nullable
  private ActionDTO mapAction(String name) {
    try {
      return ActionDTO.fromValue(name);
    } catch (IllegalArgumentException e) {
      log.warn("Unknown Action [{}], skipping", name);
      return null;
    }
  }
}
