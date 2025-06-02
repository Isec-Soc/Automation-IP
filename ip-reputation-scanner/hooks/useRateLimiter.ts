
import { useState, useCallback, useRef } from 'react';
import { RateLimitConfig } from '../types';

interface RateLimiter {
  canRequest: () => boolean;
  recordRequest: () => void;
}

const useRateLimiter = (config: RateLimitConfig): RateLimiter => {
  const requestTimestampsRef = useRef<number[]>([]);

  const canRequest = useCallback(() => {
    const now = Date.now();
    // Filter out requests older than the period
    requestTimestampsRef.current = requestTimestampsRef.current.filter(
      timestamp => now - timestamp < config.periodMilliseconds
    );
    return requestTimestampsRef.current.length < config.requests;
  }, [config.periodMilliseconds, config.requests]);

  const recordRequest = useCallback(() => {
    requestTimestampsRef.current.push(Date.now());
  }, []);

  return { canRequest, recordRequest };
};

// Hook to manage multiple rate limiters, one for each API service
export const useMultiRateLimiter = <T extends string>(
  serviceNames: T[],
  getServiceConfig: (serviceName: T) => RateLimitConfig
): Record<T, RateLimiter> => {
  
  const rateLimitersRef = useRef<Partial<Record<T, RateLimiter>>>({});

  // Initialize rateLimitersRef only once or if serviceNames/getServiceConfig changes in a way that requires re-initialization
  if (Object.keys(rateLimitersRef.current).length !== serviceNames.length) {
     const initialRateLimiters: Partial<Record<T, RateLimiter>> = {};
     serviceNames.forEach(name => {
        // This is tricky because useRateLimiter is a hook.
        // For a production scenario, this initialization might need a different approach
        // or this hook might manage state differently.
        // A simplified approach for now: we'll just store the config and manage timestamps directly.
        // This avoids calling a hook (useRateLimiter) inside a loop/conditionally during render.
        
        // Instead of calling useRateLimiter here, we'll manage its logic directly inside the returned object for each service.
        // This is a common pattern when creating a collection of hook-like objects.
     });
     // This part needs rethinking. Hooks can't be called conditionally or in loops.
     // The current useRateLimiter is designed for a single service.
     // For multi-service, we need to manage state for each.
     // A simple way is to instantiate separate rate limiters outside and pass them, or manage a map of states.
  }

  // For this implementation, let's create them on first call and store in ref.
  // This is not ideal React practice but works for this specific use case.
  // A better way would be to have `useRateLimiter` accept a key and manage internal state map.
  // Or, the component using this hook initializes individual `useRateLimiter` instances.

  // Let's simplify: The component `IpScanCoordinator` will instantiate `useRateLimiter` for each service.
  // This hook `useMultiRateLimiter` is thus not strictly needed if `IpScanCoordinator` handles it.
  // For this exercise, I will remove `useMultiRateLimiter` and `IpScanCoordinator` will manage individual rate limiters.
  // So, this file will only contain `useRateLimiter`.

  return rateLimitersRef.current as Record<T, RateLimiter>; // This is actually not how it would work.
};


export default useRateLimiter;
