--[[

NFQWS1 COMPATIBILITY FUNCTIONS

nfqws1 desync variants that zapret-antidpi.lua does not implement

--lua-init=@zapret-lib.lua --lua-init=@zapret-antidpi.lua --lua-init=@nfqws1-compat.lua

]]


-- nfqws1 : "--dpi-desync=hostfakesplit --dpi-desync-hostfakesplit-mod=altorder=1"
-- send order : before_host, fake host, after_host, real host. unlike "hostfakesplit" there's no second fake.
-- standard args : direction, payload, fooling, ip_id, rawsend, reconstruct. FOOLING AND REPEATS APPLIED ONLY TO FAKES.
-- arg : host=<str> - hostname template. generate hosts like "random.template". example : e8nzn.vk.com
function hostfakesplit_altorder1(ctx, desync)
	if not desync.dis.tcp then
		-- do not cutoff on related icmp
		if not desync.dis.icmp then instance_cutoff_shim(ctx, desync) end
		return
	end
	direction_cutoff_opposite(ctx, desync)
	local data = desync.reasm_data or desync.dis.payload
	if #data>0 and direction_check(desync) and payload_check(desync) then
		if replay_first(desync) then
			local pos = resolve_range(data, desync.l7payload, "host,endhost-1", true)
			if pos then
				if b_debug then DLOG("hostfakesplit_altorder1: resolved host range: "..table.concat(zero_based_pos(pos)," ")) end

				-- do not apply fooling to original parts except tcp_ts_up but apply ip_id
				local part
				local opts_orig = {rawsend = rawsend_opts_base(desync), reconstruct = {}, ipfrag = {}, ipid = desync.arg, fooling = {tcp_ts_up = desync.arg.tcp_ts_up}}
				local opts_fake = {rawsend = rawsend_opts(desync), reconstruct = reconstruct_opts(desync), ipfrag = {}, ipid = desync.arg, fooling = desync.arg}

				part = string.sub(data,1,pos[1]-1)
				if b_debug then DLOG("hostfakesplit_altorder1: sending before_host part 0-"..(pos[1]-2).." len="..#part.." : "..hexdump_dlog(part)) end
				if not rawsend_payload_segmented(desync,part,0, opts_orig) then return VERDICT_PASS end

				part = genhost(pos[2]-pos[1]+1, desync.arg.host)
				if b_debug then DLOG("hostfakesplit_altorder1: sending fake host part "..(pos[1]-1).."-"..(pos[2]-1).." len="..#part.." : "..hexdump_dlog(part)) end
				if not rawsend_payload_segmented(desync,part,pos[1]-1, opts_fake) then return VERDICT_PASS end

				part = string.sub(data,pos[2]+1)
				if b_debug then DLOG("hostfakesplit_altorder1: sending after_host part "..pos[2].."-"..(#data-1).." len="..#part.." : "..hexdump_dlog(part)) end
				if not rawsend_payload_segmented(desync,part,pos[2], opts_orig) then return VERDICT_PASS end

				part = string.sub(data,pos[1],pos[2])
				if b_debug then DLOG("hostfakesplit_altorder1: sending real host part "..(pos[1]-1).."-"..(pos[2]-1).." len="..#part.." : "..hexdump_dlog(part)) end
				if not rawsend_payload_segmented(desync,part,pos[1]-1, opts_orig) then return VERDICT_PASS end

				replay_drop_set(desync)
				return VERDICT_DROP
			else
				DLOG("hostfakesplit_altorder1: host range cannot be resolved")
			end
		else
			DLOG("hostfakesplit_altorder1: not acting on further replay pieces")
		end
		-- drop replayed packets if reasm was sent successfully in splitted form
		if replay_drop(desync) then
			return VERDICT_DROP
		end
	end
end
