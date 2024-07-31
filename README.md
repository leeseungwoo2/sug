## 1. 백엔드 코드

### 문제점
- (계약 상세 화면) 컨트롤러 코드가 과도하게 복잡함
- 코드 자체뿐만 아니라 각 라인에서 호출하는 함수도 매우 복잡함 (예: 하단 버튼 리스트 함수)
- 주요 원인: 
  1. <b>비즈니스 로직 내 특정 회사 커스텀 코드에 대한 과도한 분기 처리</b>
  2. 컨트롤러 코드에서 Adele 버전과 React 버전 간 분기 처리
- 전통적인 MVC 서버 사이드 렌더링과 React를 혼용하는 구조적 문제
- 시간 압박으로 인한 회사별 분기문 증가로 코드 복잡성 심화
- 개발자들의 코드 수정 기피 현상 및 생산성 저하 (복잡한 코드로 인한 '폭탄 피하기' 현상)
- Config와 소스 코드 간 매칭 어려움으로 인한 이해도 저하
- 다수의 커스텀 개발로 인한 브런치 머징의 어려움
### 해결책
1. 비즈니스 로직 내 회사별 분기 처리 최소화
   - 최상위 레벨에서 한 번만 분기 처리 후 해당 비즈니스 로직 실행
2. 서비스 레이어 도입
   - 비즈니스 로직을 서비스 레이어로 이동
   - 커스텀 요구사항 발생 시 기본 서비스 레이어를 상속받아 구현
3. 공통 기능의 모듈화
   - 컴포넌트 등 공통 기능은 Mixin을 활용하여 구현

## (현) 컨트롤러 코드
```python
@access_control(ACConstants.CONTRACT, ACLookupUtils.lookup_by_enc_params, mode=ACConstants.AC_MODE_INIT)
@csrf_exempt
@spa_support_view
def get_contract_edit_view(request):
    """
    계약 상세 화면 HTML 반환
    2024.03.26. 2.9.1 속도 개선으로 리팩토링 진행함. 기존 히스토리 확인하려면 get_contract_edit_view_old 함수 확인할 것.
    :param request:
    :return:
    """
    s = Stopwatch()
    mylogger.info('REMOTE_ADDR {}'.format(request.META.get('REMOTE_ADDR')))

    no_decode = request.GET.get('no_decode', False)  # decode 스킵 옵션
    if no_decode == 'True':
        params = eval(request.GET.get('param', request.POST.get('param')))
    else:
        # param = encode_link_param(con_id=conid, contor_id=contor_id, viewmode=viewmode)
        params = request.GET.get('param', request.POST.get('param'))
        params = decode_link_param(params)
    contract_id = params['con_id']
    # 2018-11-13 화요일
    # url 조립 에러에 대한 처리
    contor_id = '' if params.get('contor_id') == '-1' else params.get('contor_id', '')  # 없으면 없는대로 가자 괜히 문자열 -1같은 값 넣지 말고
    user_id = request.session.get("USER_ID")
    viewmode = params['viewmode']
    is_from_group_list = params.get('is_from_group_list', '')
    accessmode = params.get('accessmode', 'default')  # 이메일 접근이냐 아니냐. email, default

    contract_type = params.get('contract_type', '')

    is_adele_version = ConfigManager.is_adele_version('CONF_G', request.tenant.schema_name)

    con = None
    try:
        con = BContract.objects.get(pk=contract_id, isdeleted=False)
    except ObjectDoesNotExist as deleted_contract_e:
        # mylogger.error('deleted_contract_e -> ObjectDoesNotExist {} : {}'.format(contract_id, deleted_contract_e))
        if is_adele_version:
            # 여기는 contract_detail view 까지는 접근이 가능했던 상태이나. lk_mediumcontractView 에서 잡힐때는 다른 url을 주어야한다.
            return no_display_contract_detail_in_deleted_status(request, None)

        else:
            # 1.0 버전에서는 어차피 그대로 raise 되었을 것. 여기까지 오지도 못하나 안전하게 raise 를 건다. 확인필요. TODO
            content = {
                'msg': MSGCons.trans().cmmn_warn_the_wrong_approach,
                'title': 'Message',
                'urltogo': 'GoBackURL',
            }
            return render(request, 'common/modal.html', content)

    contor_me = None
    contor = None
    try:
        if contor_id:
            contor_me = BContractor.objects.get(pk=contor_id)
            contor_me = BContractor.get_contractor_by_current_user(request.user, contor_me)
        else:
            # 언제부터인가 contor_id가 없으면 관리자, 검토자 외에는 전부 쳐내고 있었다. contractor의 정보를 가지고 와서 contor_id 를 넣어준다.
            contor = BContractor.get_contractor_by_user_id(contract_id, user_id)
            if contor:
                # 현재 유저가 contor일 경우엔 contor_id를 가져와준다.
                contor_id = contor.id
    except ObjectDoesNotExist as ignored:
        # 원래 contor_me는 없어도 접근 가능해야 하기 때문에..
        pass

    is_before_v28 = ConfigManager.is_before_v28('CONF_G', request.tenant.schema_name)
    is_before_v28_or_stamp = is_before_v28 or contract_type == CONS.CONTRACT_STAMP
    is_only_link_view_user = contor_me and contor_me.is_only_link_view_user()

    # 접근권한 확인, 상단의 access_control 이 이미 해당 동작을 수행한다.
    # SecurityFilter.check_contract_access(request, con)

    external_company_detail_id = ''

    # 계약 접근시 해당 계약의 보안등급을 가지고 가야 여러모로 편하다
    security_grade_id = con.template.security_grade_id
    is_contract_H = False
    if security_grade_id:
        is_contract_H = True if con.template.security_grade.type == CONS.SECURITY_GRADES_H else False

    # 로그인을 확인한다.
    # 보강 처리
    # by wsKim

    if 'REQUEST_APPROVAL' == params.get('access_mode', ''):
        current_contractor_filter = con.bcontractor_set.filter(isdeleted=False, user_id=user_id)
        if current_contractor_filter.exists():
            contor_me = current_contractor_filter.last()
            contor_id = contor_me.id
        else:
            current_user = User.objects.get(pk=user_id)
            if current_user:
                # 관련인으로 추가
                contractor = BContractor.objects.create(name=current_user.first_name,
                                                        email=current_user.email,
                                                        contract=con, responsibility=CONS.CONTOR_RES_WATCH,
                                                        classification=[CONS.CONTOR_USER_VIEW,
                                                                        CONS.CONTOR_EXTRA_ADDED],
                                                        user=current_user)
                # mylogger.info("[새로운 contractor 추가] {} ".format(contractor))
            else:
                content = {
                    'msg': _(MSGCons.trans().cmmn_warn_access_is_only_available_to_those_registered_as_legal_users),
                    'title': 'Message',
                    'urltogo': 'GoBackURL',
                }
                return render(request, 'common/modal.html', content)
            # end of else

    elif isEmpty(contor_id) and ('SECURITY_POST_ONLY' == params.get('access_mode', '')):
        # # 개발할때만 get 허용
        # if not request.method=='POST':
        #     if CONS.BUPTLE_SERVER_ENV=='LOCAL':
        #         pass
        #     else:
        #         raise BizException('Not supported! Invalid access.')

        current_contractor_filter = con.bcontractor_set.filter(isdeleted=False, user_id=user_id)
        if current_contractor_filter.exists():
            contor_me = current_contractor_filter.last()
            contor_id = contor_me.id
        else:
            # contor 에 없음.
            # 관리자 법무검토자면 통과
            if (isAdminLevelUser(request) or isLawyerUser(request)):
                pass
            else:
                # 아니라면 품의참조자에 등록되었는지 확인 후 등록되었다면 동적으로 관련인에 추가하고 조회 통과
                q_filter = Q(user_identifier_no_array__icontains=[request.session['EMPLOYEE_NO']]) | \
                           Q(user_identifier_no_array__icontains=[request.session['EMAIL_ID'].split('@')[0]])
                access_info_filter = BContract_approval_access_info.objects.filter(q_filter, isdeleted=False,
                                                                                   contract_no_array__icontains=[
                                                                                       con.id])

                if access_info_filter.exists():
                    # 관련인으로 추가
                    current_user = User.objects.get(pk=user_id)
                    contractor = BContractor.objects.create(name=current_user.first_name,
                                                            email=current_user.email,
                                                            contract=con, responsibility=CONS.CONTOR_RES_WATCH,
                                                            classification=[CONS.CONTOR_USER_VIEW,
                                                                            CONS.CONTOR_EXTRA_ADDED],
                                                            user=current_user)
                    # mylogger.info("[새로운 contractor 추가] {} ".format(contractor))
                else:
                    return render(request, 'common/modal_noframe.html',
                                  {'msg': '{} {} : {}'.format(MSGCons.trans().cmmn_error_no_access_authority,
                                                              request.session['EMPLOYEE_NO'],
                                                              request.session['EMAIL_ID']),
                                   'title': 'Message', 'urltogo': 'GoBackURL'})

        # POST 라면 헤더에 시큐리티가 있어야한다.
        # TODO 체크 헤더에 basic auth 이전 단계에서 체크하고 옴.
        if request.META.get('HTTP_AUTHORIZATION'):
            # check_basic_http_auth(request)
            pass
        else:
            # raise UserDisplayMsgException('Invalid access. not found. HTTP_AUTHORIZATION.')
            pass

        # mylogger.info("링크 - 입장허용 SECURITY_POST_ONLY 찾은 contor_me -> " + str(contor_me))

    elif isEmpty(contor_id) and isEmpty(user_id):

        print(" :: contor_id 및 user_id 모두 미존재, 강제 Redirecting....")

        content = {
            'msg': MSGCons.trans().cmmn_warn_the_wrong_approach,
            'title': 'Message',
            'urltogo': 'GoBackURL',
        }
        return render(request, 'common/modal.html', content)

    elif not isEmpty(contor_id) and isEmpty(user_id):

        print(" :: contor_id 존재, checkuserauth_session 체크 콜...")

        con = BContract.objects.get(pk=contract_id)
        contor_me = BContractor.objects.get(pk=contor_id)

        # 20190228 내부인이지만. 계약상대방으로 등록된 경우. 링크뷰를 통하여 접근하도록 한다.
        if contor_me.is_opposite_contractor() and not contor_me.is_outer_user():
            viewmode = 'link'
            request.session['link_view_contorid'] = contor_me.id
            if con.status_on_workflow in [CONS.CONT_STS_WF_REJECTED_CLOSED]:
                return render(request, 'common/modal_noframe.html',
                              {'msg': MSGCons.trans().contract_error_it_is_a_deleted_contract_or_a_wrong_approach,
                               'title': 'Message', 'urltogo': 'GoBackURL'})
        else:
            re = checkuserauth_session(request, con, contor_me, viewmode)
            if re != None:
                return re

    elif isEmpty(contor_id) and not isEmpty(user_id):

        print(" :: user_id 존재.... Admin 혹은 LawyerUser 권한 체크.... ")

        # 대교 핫픽스. 그룹관리자는 통과. 추후 contract랑 엮는다.
        if isAdminLevelUser(request) or isGroupAdminUser(request):
            pass
        elif UserPermissionUtils.is_dept_contract(request, con):
            # 같은 부서원일 경우도 일단 통과시킨다.
            pass
        else:
            if is_adele_version:
                return ApiService.build_view_message(request, 'common/error_page_expireddata_ver2.html', None)
            else:
                content = {
                    'msg': MSGCons.trans().contract_warn_only_related_to_the_relevant_contract_can_be_accessed,
                    'title': 'Message',
                    'urltogo': 'GoBackURL',
                }
                return render(request, 'common/modal.html', content)

        # end of else

    elif not isEmpty(contor_id) and not isEmpty(user_id):

        print(" :: contor_id 및 user_id 모두 존재, checkuserauth_session 체크 콜...")
        # contor_me = BContractor.objects.get(pk=contor_id)
        contor_me = contor or BContractor.objects.get(pk=contor_id)
        contor_me = BContractor.get_contractor_by_current_user(request.user, contor_me)
        # 20190228 내부인이지만. 계약상대방으로 등록된 경우. 링크뷰를 통하여 접근하도록 한다.
        if contor_me.is_opposite_contractor() and not contor_me.is_outer_user():
            viewmode = 'link'
            request.session['link_view_contorid'] = contor_me.id
            if con.status_on_workflow in [CONS.CONT_STS_WF_REJECTED_CLOSED]:
                return render(request, 'common/modal_noframe.html',
                              {'msg': MSGCons.trans().contract_error_it_is_a_deleted_contract_or_a_wrong_approach,
                               'title': 'Message', 'urltogo': 'GoBackURL'})

        # 외부변호사는 통과시키되, 검토중 단계가 아니면 접근하지 못한다
        elif ConfigManager.is_component_enabled('CONF_C', request.tenant.id,
                                                CONS_COMPONENT.CMPNT142_OUTER_LAWYER_BF) and request.user.userprofile.is_restricted_user():
            if con.status_on_workflow in [CONS.CONT_STS_WF_LEGAL_REVIEW]:
                pass
            else:
                return render(request, 'common/modal_noframe.html',
                              {'msg': MSGCons.trans().cmmn_no_access_permission,
                               'title': 'Message', 'urltogo': '/get_dashboard_view/'})
        else:
            re = checkuserauth_session(request, con, contor_me, viewmode)
            if re != None:
                return re
    # end of elif

    doc = con.bdocument_set.filter(isdeleted=False).last()

    # 231226긴급장애건
    DocumentUtils.check_big_html_body_doc(doc)

    sign_count_not_exists = BSignature.objects.filter(document__id=doc.id, isdeleted=False).count()

    if contor_me is None:
        contor_me = contor or con.bcontractor_set.filter(user=request.user, isdeleted=False).last()

    # BContractor =========== [S]
    current_contractor_user_id = contor_me.user_id if contor_me else None
    current_contractor_id = contor_me.id if contor_me else None
    current_contractor_roles = (
        ContractHelper.get_current_contractor_roles(con.id, current_contractor_user_id)
        if current_contractor_user_id else
        ContractHelper.get_current_contractor_roles_by_contractor_id(current_contractor_id)
    )

    is_current_contractor_reviewer = ContractorRole.REVIEWER in current_contractor_roles
    # BContractor =========== [E]

    # 텀생성 접근불가 확인 (2.9.1 속도 개선으로 추가된 코드)
    if (
        not is_before_v28_or_stamp
        and con.status_on_workflow == CONS.CONT_STS_WF_LEGAL_TERM_CREATE
        and contor_me is not None
        and not is_current_contractor_reviewer
    ):
        return ApiService.build_view_message(
            request, 'common/page_go_back.html', None,
            MSGCons.trans().contract_guide_legal_team_we_are_waiting_for_the_creation_of_a_new_contract_it_cannot_be_viewed_until_creation_is_complete
        )

    # viewmode 관련수정
    if is_only_link_view_user:
        viewmode = 'link'

    # 속도개선: DB 히트 줄이기
    status_on_workflow = con.status_on_workflow
    is_contract_completed = status_on_workflow in CONS.CONT_GRP_STS_DONE
    is_con_status_complete = status_on_workflow == CONS.CONT_STS_WF_COMPLETE
    # https://repo.yona.io/Buptle/BuptleBiz/issue/561#comment-7457
    # 561_20190319_부서장 요약 내용으로 승인
    # 첨부파일 노출 여부를 정하는 로직 추가 wskim

    # is_not_attach_show = is_contract_completed or CONS.CONT_STS_WF_WAIT_DEP_APPROVAL == status_on_workflow
    is_not_attach_show = CONS.CONT_STS_WF_WAIT_DEP_APPROVAL == status_on_workflow

    # 계약 완료 이후에도 첨부파일 추가 가능 -> 2024.01.08 디폴트 기능으로 변경
    # if ConfigManager.is_module_enabled('CONF_C_DAEKYO_FNF_HANSSEM', request, CONS_SYS.CONTRACT_FILE_UPDATE_ENABLE) and is_contract_completed:
    #     is_not_attach_show = False

    # https://pm.buptle.com/redmine/issues/96
    # Change #96_20190326_다중발송 계약서의 첨부파일 임시 기능 제한 이슈
    # 다중발송 계약일때( 마스터, 차일드 둘다 적용) 첨부파일 TAB 비노출 wsKim
    is_not_attach_tab_show = con.is_master_contract() or con.is_child_contract()

    # contor_me 가 법무팀 검토자 혹은 관리자인지.
    _s_u_pass = is_admin_user(request.user)
    if contor_me:
        _s_u_pass = _s_u_pass or is_current_contractor_reviewer

    # 전자 서명/종이 서명 방식인지 체크
    workflow_sign_type = ContractHelper.get_contract_workflow_sign_type(con.workflow_id, con.workflow_rev_num)

    is_digital_sign = workflow_sign_type == CONS.CONT_SIGN_DIGITAL
    is_paper_sign = workflow_sign_type == CONS.CONT_SIGN_PAPER

    # 계약 상태 변경으로 완료된 계약일 경우 접근 시 Notification을 제거함
    if con.status_on_workflow == CONS.CONT_STS_WF_COMPLETE and contor_me and contor_me.user_id:
        BNotification.update_inactive_by_target_user_id(CONS.CONTRACT, con.id, contor_me.user_id)

    # 계약에 참여한 사람인지 확인하기
    is_own_data = True
    if not request.user.is_anonymous():
        is_own_data = contor_me is not None
    is_only_viewer = isOnlyViewer(request, is_own_data)

    # 계약 기안자 파악하기
    creator_user_id = UserProfile.get_user_id_by_userprofile_id(con.userprofile_id)
    is_creator = creator_user_id == request.user.id

    # 프로세스 바
    contract_process_view = ''
    if is_before_v28_or_stamp:
        contract_process_list = BWorkflow_Process.get_workflow_process_list(con.workflow_id, con.workflow_rev_num)
        contract_process_view = getContractStatusViewList_new(request, con, contract_process_list)

    # 인감 관련
    # 인감 데이터 상단 부분 화면 단에서 빠져 아래 코드는 더이상 필요 없다. ( 일단 냅둠 )
    is_module_enabled_seal_stamp = ConfigManager.is_module_enabled('CONF_G', request, CONS_SYS.SEAL_STAMP)
    is_module_enabled_detail_noti = ConfigManager.is_module_enabled('CONF_C_HANSSEM', request,
                                                                    CONS_SYS.SHOW_CONTRACT_DETAIL_NOTI)

    contract_option_seal_stamp = None
    if is_module_enabled_seal_stamp or (is_before_v28_or_stamp or is_module_enabled_detail_noti):
        contract_option_seal_stamp = BContract_Option.objects.filter(
            contract_id=contract_id,
            view_data__key_name="seal_stamp_data",
        ).last()

    used_seal_stamp_data = {}
    if contract_option_seal_stamp and (is_before_v28_or_stamp or is_module_enabled_detail_noti):
        used_seal_stamp_data['view_code'] = contract_option_seal_stamp.view_data.get("seal_stamp_view_code")
        used_seal_stamp_data['name'] = contract_option_seal_stamp.view_data.get("seal_stamp_name")

    # 인감 History 없을 시 생성 코드 ( 기존 데이터 때문에 등록하는 과정을 거쳐야 한다. )
    # transaction 필요 없음
    if is_module_enabled_seal_stamp:
        contract_stamp_history = BContract_history.objects.filter(
            contract_id=contract_id,
            action_type__in=CONS.CON_GRP_ACTP_SEAL_PROCESS,
            isdeleted=False,
        ).last()

        if contract_stamp_history:
            if contract_stamp_history.extra_info.get("text_variable") is None:
                # SEAL_STAMP CONFIG가 있으면 contract_option_seal_stamp 존재해야 한다.
                if contract_option_seal_stamp:
                    text_variable = {
                        "인감이름": contract_option_seal_stamp.view_data.get("seal_stamp_name"),
                        "인감ID": contract_option_seal_stamp.view_data.get("seal_stamp_view_code")
                    }
                    contract_stamp_history.extra_info["text_variable"] = text_variable
                else:
                    mylogger.error("SEAL_STAMP CONFIG가 있으면 contract_option_seal_stamp 존재해야 한다. => 하지만 None 임!!".format(
                        contract_option_seal_stamp))

            contract_stamp_history.save()

    # 70일 전 알람
    contract_alarm_date = ConfigManager.get_contract_alarm_date('CONF_G', request)

    # 스켄본 등록 보여주기 위한 개수 체크
    registered_scan_doc_file_count = 0
    if ConfigManager.is_module_enabled('CONF_G', request, CONS_SYS.SHOW_REGISTERED_SCAN_DOC_FILE):
        registered_scan_doc_file_count = BRSDAttachment.objects.filter(isdeleted=False, contract_id=con.id).count()

    # 투자검토계약인지 확인 후 맞다면 몇가지 변수들을 세팅한다.
    is_invest_contract = ContractHelper.is_invest_template(request, con.template_id)
    is_shareholder_contract = ContractHelper.is_shareholder_template(request, con.template_id)
    currency_unit = con.currency_unit
    share_ratio = con.share_ratio
    special_clause = con.special_clause

    if is_invest_contract or is_shareholder_contract:
        request.session['active_first_menu'] = 'invest_manage'

    # 투자검토관련 계약이라면 추가적인 파일들을 확인 후 내려준다.
    invest_att_files = {}
    if is_invest_contract or is_shareholder_contract:
        relation_files = BInvest_files.objects.filter(isdeleted=False, file_type=CONS.INVEST_FILE_RELATION,
                                                      contract_id=con.id)
        appr_files = BInvest_files.objects.filter(isdeleted=False, file_type=CONS.INVEST_FILE_APPR, contract_id=con.id)
        relation_list = []
        appr_list = []

        if relation_files.exists():
            relation_list = []
            for one_file in relation_files:
                temp = {
                    'file_id': one_file.id,
                    'file_name': one_file.file_name,
                    'file_type': one_file.file_type
                }
                relation_list.append(temp)

        invest_att_files['relation_files'] = relation_list

        if appr_files.exists():

            for one_file in appr_files:
                temp = {
                    'file_id': one_file.id,
                    'file_name': one_file.file_name,
                    'file_type': one_file.file_type
                }
                appr_list.append(temp)

        invest_att_files['appr_files'] = appr_list

    subsidiary_info = []
    select_subsidiary_info = {}
    if ConfigManager.is_module_enabled('CONF_C_FNF_HANSSEM_2.8', request, CONS_SYS.SUBSIDIARY_MANAGE):
        subsidiary_info = BSubsidiary.get_all_subsidiary_id_and_name(request)
        select_subsidiary_info = BContract_Option.get_subsidiary_info(con)
        if select_subsidiary_info:
            select_subsidiary_info = select_subsidiary_info.get("id")

    #  법무검토자 할당
    contractors = BContractor.get_contractor(int(con.id), [CONS.CONTOR_USER_REVIEW])
    contractors = remove_secondary_reviewer(request, contractors=contractors)

    is_reviewer_exists = contractors and len(contractors) > 0
    contract_review_lawyer_arr = []
    if is_reviewer_exists:
        for contractor in contractors:
            contract_review_lawyer_arr.append(tooltip_span_confirm_and_laywer(request, contractor))
        # end of for
    contract_review_lawyer = "".join(contract_review_lawyer_arr)

    # 다중 계약서
    documents_by_group = []

    is_multi_doc = (
        ConfigManager.is_module_enabled('CONF_G', request, CONS_SYS.CON_MULTI_DOC_ENABLED)
        and MultiDocHelper.is_multi_doc_contract(con)
    )

    if is_multi_doc:
        # doc_filter = MultiDocHelper.doc_filter_by_group(con)
        doc_filter = BDocument.get_current_doc_new_with_request(request, con, request.user, contor_me, is_multi_doc)

        if not isinstance(doc_filter, BDocument):
            for doc in doc_filter:
                documents_by_group.append(dict(
                    id=doc.id,
                    file_name=doc.scanfile_name if (doc.file_name == 'filename') or (
                                doc.file_name == '') else doc.file_name,
                    group=doc.group,
                ))
        doc = doc_filter.first()  # first() 하면 group=1 인 doc.
    else:
        doc = BDocument.get_current_doc_new_with_request(request, con, request.user, contor_me)

    # 클라우드 운영에서 미사용 중인 컨피그로 주석 처리(2.9.1 속도개선)
    # 삼우건축 사용 계열사 문서 계약인지 여부
    # is_custom_subsidiary_contract = ConfigManager.is_custom_subsidiary_contract('CONF_C', request.tenant.id,
    #                                                                             con.template_id)
    # 삼우건축 사용 계열사 수신 계약인지 여부
    # is_custom_subsidiary_receive_contract = ConfigManager.is_custom_subsidiary_receive_contract('CONF_C',
    #                                                                                             request.tenant.id,
    #                                                                                             con.template_id)

    # 상대방 로직
    bcontract_main_contractor_comp_list = []

    bcontractmaincontractorcomp_list = BContractMainContractorComp.objects.filter(
        isdeleted=False,
        contract_id=int(con.id),
    ).order_by('company_name')

    for obj in bcontractmaincontractorcomp_list:
        obj_tobe = {}
        obj_tobe["is_company"] = "Y"
        obj_tobe["id"] = obj.id
        obj_tobe["name"] = obj.company_name if not isEmpty(obj.company_name) else ''
        obj_tobe["ceo_name"] = obj.ceo_name if not isEmpty(obj.ceo_name) else ''
        obj_tobe["country_code"] = obj.country_code if not isEmpty(obj.country_code) else ''
        obj_tobe["corp_reg_number"] = obj.corp_reg_number if not isEmpty(obj.corp_reg_number) else ''
        obj_tobe["email"] = obj.email if not isEmpty(obj.email) else ''
        obj_tobe["mobile_number"] = obj.mobile_number if not isEmpty(obj.mobile_number) else ''
        obj_tobe["external_company_id"] = obj.bexternal_company_id if obj.bexternal_company_id else ''
        bcontract_main_contractor_comp_list.append(obj_tobe)

    bcontractmaincontractorprsn_list = BContractMainContractorPRSN.objects.filter(
        isdeleted=False,
        contract_id=int(con.id),
    ).order_by('name')

    for obj in bcontractmaincontractorprsn_list:
        obj_tobe = {}
        obj_tobe["is_company"] = "N"
        obj_tobe["id"] = obj.id
        obj_tobe["name"] = obj.name if not isEmpty(obj.name) else ''
        obj_tobe["ceo_name"] = ''
        obj_tobe["country_code"] = ''
        obj_tobe["corp_reg_number"] = ''
        obj_tobe["email"] = obj.email if not isEmpty(obj.email) else ''
        obj_tobe["mobile_number"] = obj.mobile_number if not isEmpty(obj.mobile_number) else ''

        bcontract_main_contractor_comp_list.append(obj_tobe)

    custom_disable_status = ConfigManager.get_sys_config_value('CONF_C_HANSSEM_WOOMI_IIC', request,
                                                               CONS_SYS.DISABLE_CONTRACT_EDIT)

    is_editable_by_status = CONS.CONT_STS_WF_LEGAL_APPROVED > con.status_on_workflow
    if custom_disable_status:
        is_editable_by_status = is_editable_by_status and int(custom_disable_status) > con.status_on_workflow

    is_contor_me_master = contor_me and bool(contor_me.isMaster())
    is_admin = isAdminUser(request)
    is_lawyer = isLawyerUser(request)

    DEFAULT_ITEM_EDITABLE = is_editable_by_status and (
        contor_me and (is_contor_me_master or ContractorRole.DEPT_REVIEWER in current_contractor_roles) or is_admin or is_lawyer
    )

    # FNF - 법무팀은 계약 완료 전까지는 계약 시작일/종료일 수정 가능.
    contract_date_editable = False
    if (
        ConfigManager.is_module_enabled(
            'CONF_C_FNF_EFLASK', request, CONS_SYS.ENABLED_EDIT_CONTRACT_DATE_ON_CONTRACT_DELETE_META_VIEW
        ) and con.status_on_workflow < CONS.CONT_STS_WF_CON_REJECTED and isLawyerUser(request)
    ):
        contract_date_editable = True

    # s4 = Stopwatch()
    btn_ids = (
        ContractViewButtonManager.get_enable_button_ids(request, con, contor_me, request.user, doc.id)
        if is_before_v28_or_stamp else []
    )
    # mylogger.info("btn_ids: {}".format(s4.stop()))

    # 외부인인지 판별
    is_outer_user = request.user.is_anonymous() or is_only_link_view_user

    open_previous_progress_accordion = need_to_open_previous_progress_accordion(con, request.user)  # True or False

    # 속도개선 PDF 초기화 댕기기
    IS_SCAN_FILE = doc.is_only_scan_file(con.classification)
    CAN_PDF_VIEW = doc.can_pdf_view(con.classification)

    # init_contract_view 에도 동일코드가 있다.. 일단 테스트 완료 후, 추후 리팩토링때 정리.
    registered_scan_doc_file_count = 0
    is_jpg_scan_doc_file = False
    if ConfigManager.is_module_enabled('CONF_G', request, CONS_SYS.SHOW_REGISTERED_SCAN_DOC_FILE):
        registered_scan_doc_file_count = BRSDAttachment.objects.filter(isdeleted=False, contract_id=con.id).count()
        scan_doc_attach = BRSDAttachment.objects.filter(isdeleted=False, contract_id=con.id).last()
        if scan_doc_attach is not None:
            filename, file_extension = os.path.splitext(scan_doc_attach.name)
            if file_extension.lower() == '.jpg':
                is_jpg_scan_doc_file = True

    content = {
        'contract_id': contract_id,
        'contract_name': con.name,
        'contor_id': contor_me.id if contor_me else '-1',
        'contor_me': contor_me,
        'viewmode': viewmode,
        'doc_id': doc.id,
        'btn_ids': btn_ids,
        'accessmode': accessmode,
        'is_contract_completed': is_contract_completed,
        'is_con_status_complete': is_con_status_complete,
        'is_not_attach_show': is_not_attach_show,
        'is_not_attach_tab_show': is_not_attach_tab_show,
        'is_from_group_list': is_from_group_list,
        'is_online_contract': bool(con.is_online_contract()),
        'is_master_contract': bool(con.is_master_contract()),
        'is_child_contract': bool(con.is_child_contract()),
        '_s_u_pass': bool(_s_u_pass),
        '_dept_approval_code': con.workflow.get_dept_approval_code(con) if is_before_v28_or_stamp else '',
        'sign_count_not_exists': sign_count_not_exists,
        'security_grade_id': security_grade_id if security_grade_id else 'None',
        'is_contract_H': is_contract_H,
        'is_affiliate': False,
        'is_send_time': False,
        'is_digital_sign': is_digital_sign,
        'is_paper_sign': is_paper_sign,
        'is_affiliate_contract': False,
        'is_web_form_contract': False,
        'is_affiliate_sign_template': False,
        'is_receive_time': False,
        'is_delay_30': False,
        'status_on_workflow': con.status_on_workflow,
        'status_on_sign_process': con.status_on_sign_process,  # sk 사인프로세스용 추가
        'is_only_viewer': is_only_viewer,
        'contract': con,
        'contract_process_view': contract_process_view,
        'is_creator': is_creator,
        'used_seal_stamp_data': used_seal_stamp_data,
        'contract_alarm_date': contract_alarm_date,
        'template_name': con.template.name,
        'template_id': con.template_id,
        'subsidiary_name': (
            con.userprofile.subsidiary_name
            if is_before_v28_or_stamp or
               ConfigManager.is_module_enabled('CONF_C_FNF_HANSSEM', request, CONS_SYS.CONTRACT_SUBSIDIARY_NAME)
            else ''
        ),
        'is_seal_process_writing': con.get_is_seal_process_writing() if is_before_v28_or_stamp else False,
        'registered_scan_doc_file_count': registered_scan_doc_file_count,
        'is_jpg_scan_doc_file': is_jpg_scan_doc_file,
        'is_invest_contract': is_invest_contract,
        'is_shareholder_contract': is_shareholder_contract,
        'currency_unit': currency_unit,
        'share_ratio': share_ratio,
        'special_clause': special_clause,
        'invest_att_files': invest_att_files,
        'is_multiple_docx': con.is_multiple_docx(),
        'contract_option_list': BContract_Option.get_contract_option_list(con) if is_before_v28_or_stamp else [],
        'is_contract_cancel_enable': con.is_contract_sent_cancel_enabled() if is_before_v28_or_stamp else False,
        'subsidiary_info': subsidiary_info,
        'select_subsidiary_info': select_subsidiary_info,
        'is_prsn_info_collected': (
            con.get_contract_option_with_key('is_prsn_info_collected') if is_before_v28_or_stamp else False
        ),
        'is_pay_stamp_duty': (
            con.get_contract_option_with_key('is_pay_stamp_duty') if is_before_v28_or_stamp else False
        ),
        'stamp_duty_info': (
            con.get_contract_option_with_key('stamp_duty_info') if is_before_v28_or_stamp else ''
        ),
        'is_opposite_editable_disabled': (
            con.get_contract_option_with_key('is_opposite_editable_disabled')
            if ConfigManager.is_module_enabled('CONF_C_FNF_WOOMI_IIC', request,
                                               CONS_SYS.DISABLED_OPPOSITE_EDIT_CONTRACT)
            else ''
        ),
        'view_code': con.view_code,
        'documents_by_group': documents_by_group,
        'documents_id_list': [doc['id'] for doc in documents_by_group],
        'documents_id_list_comma_str': ','.join([str(doc['id']) for doc in documents_by_group]),
        'is_multi_doc': is_multi_doc,
        'contract_review_lawyer': contract_review_lawyer,
        'is_custom_subsidiary_contract': False,
        'is_custom_subsidiary_receive_contract': False,
        'bcontract_main_contractor_comp_list': bcontract_main_contractor_comp_list,
        'DEFAULT_ITEM_EDITABLE': DEFAULT_ITEM_EDITABLE,
        'is_contract_web_content': False,
        'is_outer_user': is_outer_user,
        'contorme_is_creator': ContractorRole.CREATOR in current_contractor_roles,
        'contorme_is_reviewer': is_current_contractor_reviewer,
        'doc_file_name': doc.file_name if doc and doc.file_name else '',
        'contract_date_editable': contract_date_editable,
        'sign_process_type': con.sign_process_type,
        'contract_etc_type': contract_type if contract_type else con.etc_type,
        'workflow_id': con.workflow_id,  # 속도개선으로 변경되는 프론트구조에 필요해서 추가
        'open_previous_progress_accordion': open_previous_progress_accordion,  # 속도개선으로 변경되는 프론트구조에 필요해서 추가
        'IS_SCAN_FILE': IS_SCAN_FILE,
        'CAN_PDF_VIEW': CAN_PDF_VIEW,
        'is_wk_has_term': bool(con.workflow.is_term(con)),
    }

    filter_secondary_reviewer_in_content(request, con=con, content=content)
    get_seal_process_stamp_info(request=request, contract=con, content=content)  # sk커스텀 사인날인

    if (False or False) and external_company_detail_id:
        content['external_company_detail_id'] = external_company_detail_id.pk

    if ConfigManager.is_module_enabled('CONF_C_OHOUSE', request, CONS_SYS.NO_SIGN_MULTI_CONTRACT):
        if con.workflow.is_only_review_contract(con):
            if con.contract_type == CONS.CONT_TYPE_MASTER or con.contract_type == CONS.CONT_TYPE_CHILD:
                content['is_no_sign_multi_contract'] = True

    # 2.8 버전 변경된 진행 단계 문구 적용
    if not is_before_v28:
        content["status_text_v28"] = get_contract_progress_status_text_v28(
            request, con.id, con.status_on_workflow,
            is_reviewer_exists=is_reviewer_exists,
        )

    if ConfigManager.is_module_enabled('CONF_C_GREENLABS', request, CONS_SYS.MODULE_CONTRACT_WEB_CONTENT):
        contract_user_ctg = BUserCategoriesContract.objects.filter(isdeleted=False, contract_id=con.id).last()
        if contract_user_ctg:
            contract_ctg = BUserCategories.objects.get(pk=contract_user_ctg.user_categories_id)
            if contract_ctg.depth == 1 and str(
                    contract_ctg.origin_template_id) in ConfigManager.get_contract_web_content_ctg_root_folder_id(
                    'CONF_C_GREENLABS', request):
                # 현재 계약의 최상위 카테고리가 전자계약으로 등록된 카테고리일 경우
                content['is_contract_web_content'] = True
            elif contract_ctg.depth == 2:
                # depth가 2일 경우 usercategory에 parent를 저장하지 않는 경우가 있을 수 있다 -> template에서 직접 찾는다.
                parent_ctg = BTemplate.objects.get(pk=contract_ctg.origin_template_id).parent_folder_id
                if str(parent_ctg) in ConfigManager.get_contract_web_content_ctg_root_folder_id('CONF_C_GREENLABS',
                                                                                                request):
                    content['is_contract_web_content'] = True

    is_related_user_can_edit(request=request, contor_me=contor_me, content=content, contract=con)

    if is_adele_version:
        if is_only_link_view_user:
            cancel_log = BContract_Action.objects.filter(contract_id=contract_id).last()
            if cancel_log and CONS.CONT_ACTP_CANCEL_SENT_CONTRACT == cancel_log.action_type:
                return no_display_contract_detail_in_cancelled_status(request, contor_me)

            if is_multi_doc:
                # 다중 계약서
                return ApiService.build_view_message(request, 'contract/multi_doc_contract_detail_link_view.html',
                                                     content)
            return ApiService.build_view_message(request, 'contract/contract_detail_link_view.html', content)
        else:
            # 패치. 외부인이 아닌걸로 판정나면 세션에서 flag 값을 지워준다.
            request.session['link_view_confirm'] = False
            if is_before_v28:
                if ConfigManager.is_module_enabled('CONF_C_DAEKYO_FNF_HANSSEM_2.8', request,
                                                   CONS_SYS.NEW_PGROGRESS_PROCESS):
                    if contract_type == CONS.CONTRACT_STAMP:
                        return ApiService.build_view_message(request,
                                                             'contract/stamp/contract_stamp_detail_inner_new.html',
                                                             content)
                    else:
                        if is_multi_doc:
                            # 다중 계약서
                            return ApiService.build_view_message(request,
                                                                 'contract/multi_doc_contract_detail_inner_new.html',
                                                                 content)
                        return ApiService.build_view_message(request, 'contract/contract_detail_inner_new.html',
                                                             content)
                else:
                    return ApiService.build_view_message(request, 'contract/contract_detail_inner.html', content)
            else:
                # 2.85 버전
                # if ConfigManager.is_module_enabled(request, CONS_SYS.CON_MULTI_DOC_ENABLED) and MultiDocHelper.is_multi_doc_contract(con):
                #     # 다중 계약서
                #     return ApiService.build_view_message(request, 'contract/contract_detail_inner_v28_base.html',
                #                                          content)
                mylogger.info("[2.9.1 속도 개선] after build: base  html return  :{},{}"
                    .format(s.stop(), 'for end###########################################################################')
                )
                if contract_type == CONS.CONTRACT_STAMP:
                    return ApiService.build_view_message(request,
                                                         'contract/stamp/contract_stamp_detail_inner_new.html',
                                                         content)
                return ApiService.build_view_message(request, 'contract/contract_detail_inner_v28_base.html', content)

    else:
        return ApiService.build_view_message(request, 'contract/manage_contract_edit.html', content)
```

## (현)버튼 list 함수
```python

class ContractViewButtonManager():
    @staticmethod
    def get_enable_button_ids(request, contract, contractor, curr_user, doc_id):
        # contractor 는 현재 세션 유저로 보정해주어야 한다.
        contractor = BContractor.get_contractor_by_current_user( curr_user, contractor )
        # 계약에 참석여부
        IS_MEMBER_OF = BContractor.is_member_of(contract.id, contractor.id) if contractor is not None else False

        status_on_workflow = contract.status_on_workflow
        IS_ADMIN = is_admin_user(curr_user)
        IS_SYS_LAWYER = is_lawyer_user(curr_user)
        IS_MASTER = False if contractor is None else contractor.isMaster()
        IS_LAWYER_REVIEWER = False if contractor is None else contractor.is_reviewer()
        IS_DEPT_REVIEWER = False if contractor is None else contractor.is_dept_reviewer()
        if contractor and not IS_DEPT_REVIEWER:
            IS_DEPT_REVIEWER = BContractor.has_user_dept_role(contractor)
        IS_LAWYER_MGR_REVIEWER = False if contractor is None else contractor.has_confirm()
        IS_OUTTER_MEMBER = False if contractor is None else contractor.is_only_link_view_user()
        IS_SIGN_REVIEWER = False if contractor is None else contractor.is_sign_reviewer()
        IS_DEPT_MEMBER = UserPermissionUtils.is_dept_contract(request, contract)
        if contractor and contractor.has_confirm() and CONS.CONT_STS_WF_WAIT_LEGAL_APPROVAL == status_on_workflow:
            IS_LAWYER_REVIEWER = False
            IS_LAWYER_MGR_REVIEWER = True

        role_dict = ContractViewButtonManager.__BUTTON_ROLE_DICT_BY_WORKFLOW_STATUS
        add_button_role_draft_appr(request=request, role_dict=role_dict)
        add_button_role_draft_appr_sign_seal_process(request=request, role_dict=role_dict)
        add_button_role_dept_appr(request=request, role_dict=role_dict)
        add_button_role_law_start_or_stop(request=request, role_dict=role_dict)
        add_button_role_circ_before_review(request=request, role_dict=role_dict)
        add_button_role_appr_before_req_legal_head(request=request, role_dict=role_dict)
        add_button_role_appr_after_review_done(request=request, role_dict=role_dict)
        add_button_role_circ_before_legal_head_approved(request=request, role_dict=role_dict)
        add_button_role_review_complete(request=request, role_dict=role_dict)
        add_button_role_legal_approved_complete(request=request, role_dict=role_dict)
        add_user_button_role_contract_manager(request=request, role_dict=role_dict)

        btn_list = []
        role_in_key_value = None
        if IS_MASTER:
            role_in_key_value = 'CREATOR'
            btn_list.extend(ContractViewButtonManager.__BUTTON_ROLE_DICT_BY_WORKFLOW_STATUS[status_on_workflow][role_in_key_value])
        elif IS_OUTTER_MEMBER:
            role_in_key_value = 'OUTTER_MEMBER'

        if IS_DEPT_REVIEWER:
            role_in_key_value = 'DEPT_REVIEWER'
            btn_list.extend(ContractViewButtonManager.__BUTTON_ROLE_DICT_BY_WORKFLOW_STATUS[status_on_workflow][role_in_key_value])

        if IS_SYS_LAWYER:
            role_in_key_value = 'SYS_LAWYER'
            btn_list.extend(ContractViewButtonManager.__BUTTON_ROLE_DICT_BY_WORKFLOW_STATUS[status_on_workflow][role_in_key_value])

        if IS_LAWYER_REVIEWER:
            role_in_key_value = 'LAWYER_REVIEWER'
            btn_list.extend(ContractViewButtonManager.__BUTTON_ROLE_DICT_BY_WORKFLOW_STATUS[status_on_workflow][role_in_key_value])

        if IS_LAWYER_MGR_REVIEWER:
            role_in_key_value = 'LAWYER_MGR_REVIEWER'
            btn_list.extend(ContractViewButtonManager.__BUTTON_ROLE_DICT_BY_WORKFLOW_STATUS[status_on_workflow][role_in_key_value])

        if IS_ADMIN:
            role_in_key_value = 'ADMIN'
            btn_list.extend(ContractViewButtonManager.__BUTTON_ROLE_DICT_BY_WORKFLOW_STATUS[status_on_workflow][role_in_key_value])

        role_in_key_value = set_contract_manager_btn(request=request, role_in_key_value=role_in_key_value, btn_list=btn_list, role_dict=role_dict, status_on_workflow=status_on_workflow, contractor=contractor)

        # 2020.11.18 역할이 없는 일반 관련인인 경우 아래 __append() 함수를 타지 않고 return 되어 여기서 넣어줌
        if CONS.CONT_CLS_ONLINE == contract.classification and contractor:
            filter_classification_list = [_ for _ in contractor.classification if
                                          _ in [CONS.CONTOR_USER_DEFAULT, CONS.CONTOR_USER_VIEW]]
            if contractor.canEdit() and filter_classification_list:
                btn_list.append("conedit-save-btn")

        if role_in_key_value is None:
            pass
            #return btn_list
        else:
            tmp_list_final= ContractViewButtonManager.__BUTTON_ROLE_DICT_BY_WORKFLOW_STATUS[status_on_workflow][role_in_key_value]
            btn_list.extend(tmp_list_final)

        btn_list = list(set(btn_list))
        btn_list_copy = btn_list[:]

        # 필터, 내부적으로 copy 가 일어나므로 리턴값을 받아 참조를 덮어쓴다.
        ContractViewButtonManager.__filter_by(
            request,
            status_on_workflow,
            role_in_key_value,
            btn_list_copy,
            **{
                'contract_id': contract.id,
                'contract': contract,
                'contractor': contractor,
                'doc_id': doc_id,
                'IS_LAWYER_REVIEWER': IS_LAWYER_REVIEWER,
                'IS_LAWYER_MGR_REVIEWER': IS_LAWYER_MGR_REVIEWER,
                'IS_SYS_LAWYER': IS_SYS_LAWYER,
                'IS_ADMIN': IS_ADMIN,
                'IS_MASTER': IS_MASTER,
                'IS_SIGN_REVIEWER': IS_SIGN_REVIEWER,
                'IS_DEPT_REVIEWER': IS_DEPT_REVIEWER,
                'IS_OUTTER_MEMBER': IS_OUTTER_MEMBER,
            })

        # append, 내부적으로 copy 가 일어나므로 리턴값을 받아 참조를 덮어쓴다.
        ContractViewButtonManager.__append(
            request,
            status_on_workflow,
            role_in_key_value,
            btn_list_copy,
            **{
                'contract_id': contract.id,
                'contract': contract,
                'contractor': contractor,
                'doc_id': doc_id,
                'IS_LAWYER_REVIEWER': IS_LAWYER_REVIEWER,
                'IS_LAWYER_MGR_REVIEWER': IS_LAWYER_MGR_REVIEWER,
                'IS_MASTER': IS_MASTER,
                'IS_MEMBER_OF': IS_MEMBER_OF,
                'IS_SYS_LAWYER': IS_SYS_LAWYER,
                'IS_SIGN_REVIEWER': IS_SIGN_REVIEWER,
                'IS_DEPT_REVIEWER': IS_DEPT_REVIEWER,
            })

        # 2.8버전 상세화면용 제어버튼(유저 등록/삭제 등의 추가 제어버튼)
        if ConfigManager.is_version_28('CONF_G', request.tenant.name):
            ContractViewButtonManager.__extra(
                request,
                status_on_workflow,
                role_in_key_value,
                btn_list_copy,
                **{
                    'contract_id': contract.id,
                    'contract': contract,
                    'contractor': contractor,
                    'doc_id': doc_id,
                    'IS_LAWYER_REVIEWER': IS_LAWYER_REVIEWER,
                    'IS_LAWYER_MGR_REVIEWER': IS_LAWYER_MGR_REVIEWER,
                    'IS_MASTER': IS_MASTER,
                    'IS_MEMBER_OF': IS_MEMBER_OF,
                    'IS_SYS_LAWYER': IS_SYS_LAWYER,
                    'IS_ADMIN': IS_ADMIN,
                    'IS_SIGN_REVIEWER': IS_SIGN_REVIEWER,
                    'IS_DEPT_REVIEWER': IS_DEPT_REVIEWER,
                    'IS_DEPT_MEMBER': IS_DEPT_MEMBER,
                })

        # 텔레칩스 전송 버튼 숨김
        if 'save-action-btn' in btn_list_copy and ConfigManager.is_module_enabled('CONF_C', request, CONS_SYS.NO_SEND_BTN):
            # btn 중복 요소 제거
            btn_list_copy = list(set(btn_list_copy))
            btn_list_copy.remove('save-action-btn')
            mylogger.info(btn_list_copy)

        # 이로그는 없으면 안된다.
        mylogger.info("\n\n[BUTTON IDS] ============= {} {}".format(status_on_workflow, role_in_key_value)
                       + "\n" + ", ".join(btn_list_copy) + "\n[END BUTTON IDS]=============\n")

        sign_process_btn_enabled(contract, contractor, curr_user, btn_list_copy)
        btn_list_copy = contract_based_counsel_btn_process(request, contract=contract, btn_ids_list=btn_list_copy, contor=contractor)

        return btn_list_copy
```
## 개선된 코드 구조
### 1. 서비스 레이어 및 공통 Mixin 생성

- 기본 `ContractService` 클래스를 통해 공통 로직 구현
- 회사별 커스텀 요구사항을 위한 개별 서비스 클래스 생성
- 자주 사용되는 기능을 `Mixin`으로 구현하여 재사용성 증대
#### 주요 컴포넌트

1. **ContractManagerMixin**
   - 커스텀 담당자 및 담당자 버튼 권한 추가 로직 포함
   - Samsung과 LG 서비스에서 활용

2. **ContractService**
   - 기본적인 계약 처리 로직 구현
   - 공통 메서드 (process_request, decode_params 등) 포함
   - 하위 클래스에서 오버라이드 가능한 메서드 제공

3. **회사별 서비스 클래스**
   - SkService, SamsungService, LgService, KtService 등
   - ContractService를 상속받아 회사별 커스텀 로직 구현
   - 필요에 따라 ContractManagerMixin 활용

```python
class ContractManagerMixin:
    def add_role_button(self, request, role_dict):
        # 커스텀 담당자 및 담당자 버튼 권한 추가 로직
        role_dict['custom_role'] = 'Contract Manager'
        # 추가적인 로직을 여기에 작성
        return role_dict

class ContractService:
    def process_request(self, request):
        # 공통 로직 처리
        params = self.decode_params(request)
        contract = self.get_contract(params['con_id'])
        contor_me = self.get_contractor(params, contract, request)
        content = self.build_content(contract, contor_me, params, request)
        return self.render_view(request, content, params)

    def decode_params(self, request):
        no_decode = request.GET.get('no_decode', False)
        if no_decode == 'True':
            return eval(request.GET.get('param', request.POST.get('param')))
        else:
            params = request.GET.get('param', request.POST.get('param'))
            return decode_link_param(params)

    def get_contract(self, contract_id):
        try:
            return BContract.objects.get(pk=contract_id, isdeleted=False)
        except ObjectDoesNotExist:
            raise BizException("Contract not found")

    def get_contractor(self, params, contract, request):
        contor_id = params.get('contor_id', '')
        user_id = request.session.get("USER_ID")
        if contor_id:
            return BContractor.objects.get(pk=contor_id)
        else:
            return BContractor.get_contractor_by_user_id(contract.id, user_id)

    def build_content(self, contract, contor_me, params, request):
        # 공통 content 빌드 로직
        content = {
            'contract_id': contract.id,
            'contract_name': contract.name,
            'contor_id': contor_me.id if contor_me else '-1',
            'contor_me': contor_me,
            'viewmode': params['viewmode'],
            # 추가적인 공통 content 설정
        }
        return content

    def render_view(self, request, content, params):
        # 공통 뷰 렌더링 로직
        template_name = self.get_template_name(request)
        return render(request, template_name, content)

    def get_template_name(self, request):
        return 'contract/default_contract_detail.html'

class SkService(ContractService):
    def build_content(self, contract, contor_me, params, request):
        content = super().build_content(contract, contor_me, params, request)
        # SK의 커스텀 로직 추가
        content['custom_field'] = 'SK specific data'
        return content

    def get_template_name(self, request):
        return 'contract/sk_contract_detail.html'

class SamsungService(ContractService, ContractManagerMixin):
    def build_content(self, contract, contor_me, params, request):
        content = super().build_content(contract, contor_me, params, request)
        # Samsung의 커스텀 로직 추가
        content['custom_field'] = 'Samsung specific data'
        # 커스텀 담당자 및 담당자 버튼 권한 추가
        role_dict = {}
        content['role_dict'] = self.add_role_button(request, role_dict)
        return content

    def get_template_name(self, request):
        return 'contract/samsung_contract_detail.html'

class LgService(ContractService, ContractManagerMixin):
    def build_content(self, contract, contor_me, params, request):
        content = super().build_content(contract, contor_me, params, request)
        # LG의 커스텀 로직 추가
        content['custom_field'] = 'LG specific data'
        # 커스텀 담당자 및 담당자 버튼 권한 추가
        role_dict = {}
        content['role_dict'] = self.add_role_button(request, role_dict)
        return content

    def get_template_name(self, request):
        return 'contract/lg_contract_detail.html'

class KtService(ContractService):
    def build_content(self, contract, contor_me, params, request):
        content = super().build_content(contract, contor_me, params, request)
        # KT의 커스텀 로직 추가
        content['custom_field'] = 'KT specific data'
        return content

    def get_template_name(self, request):
        return 'contract/kt_contract_detail.html'
```
### 2. 테넌트 미들웨어
- `TenantMiddleware` 클래스를 통해 요청별 테넌트 식별 및 서비스 클래스 연결
- 테넌트 ID를 추출하여 적절한 서비스 클래스를 요청 객체에 추가
```python
class TenantMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        # 테넌트 ID를 추출하여 request 객체에 추가
        tenant_id = self.get_tenant_id(request)
        request.tenant_id = tenant_id

        # 적절한 서비스 클래스를 request 객체에 추가
        request.service_class = self.get_service_class(tenant_id)

        response = self.get_response(request)
        return response

    def get_tenant_id(self, request):
        # 테넌트 ID를 추출하는 로직 (예: 서브도메인, 헤더, 쿠키 등에서 추출)
        return request.tenant.schema_name

    def get_service_class(self, tenant_id):  # 해당 코드에서 테넌트별 Service 레이어 class를 반환
        try:
            class_name = f"{tenant_id.capitalize()}Service"
            return globals()[class_name]
        except KeyError:
            return ContractService
```
### 3. 간소화된 컨트롤러

- 복잡한 분기 로직 제거
- 테넌트별 서비스 레이어를 통해 비즈니스 로직 실행
```python
@access_control(ACConstants.CONTRACT, ACLookupUtils.lookup_by_enc_params, mode=ACConstants.AC_MODE_INIT)
@csrf_exempt
@spa_support_view
def get_contract_edit_view(request):
    service = request.service_class()
    return service.process_request(request)
```
### 4. 템플릿 구조 개선

- 기본 템플릿을 상속받아 회사별 커스텀 템플릿 구현
- Jinja 템플릿의 복잡한 분기문 제거
```html
<!-- 베이스 버전 -->

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Contract Detail</title>
</head>
<body>
    <h1>Contract Detail</h1>
    <p>Contract ID: {{ contract_id }}</p>
    <p>Contract Name: {{ contract_name }}</p>
    <!-- 공통 필드들 -->
</body>
</html>

<!-- sk 버전 : templates/contract/sk_contract_detail.html -->
{% extends "contract/base_contract_detail.html" %}

{% block content %}
    {{ super() }}
    <p>Custom Field: {{ custom_field }}</p>
    <!-- SK의 커스텀 필드들 -->
{% endblock %}

<!-- samsung 버전 : templates/contract/samsung_contract_detail.html -->
templates/contract/samsung_contract_detail.html
{% extends "contract/base_contract_detail.html" %}

{% block content %}
    {{ super() }}
    <p>Custom Field: {{ custom_field }}</p>
    <!-- Samsung의 커스텀 필드들 -->
{% endblock %}
```
## 2. 프론트 코드
```html
<header class="flex items-center paddingB-10">
    <div class="w-100P marginR-auto">
        <input class="input-text type-title" type="text" id="contract-title" name="contract-title" value="{{data.contract_name}}" onchange="CONTRACT_CONTEXT.methods.fnChangeSave(this)" {% if not DEFAULT_ITEM_EDITABLE %} readonly {% endif %}>
    </div>
{% if not CONFIG_MANAGER.is_component_enabled('CONF_C_KISED', request.tenant.id, CONS_COMP.CMPNT257_CONTRACT_BASED_ON_COUNSEL) %}
    <div class="shrink-0 fr tr contract_hd_btn" id="btn_div_contents_edit">
        {% include 'contract/include/btns_contract_contents_edit.html'%}
    </div>
{% endif %}
</header>
```
### 문제점
1. **코드 구조의 불명확성**
   - 화면 렌더링 위치 파악 어려움
   - 버튼 이벤트 바인딩의 분산으로 추적 곤란

2. **유지보수의 어려움**
   - 신규 및 기존 직원들의 코드 이해 어려움
   - 특정 회사 커스텀 코드에 대한 과도한 분기 처리

3. **레거시 코드 증가**
   - 시간 경과에 따른 레거시 코드 누적
   - 현 구조로는 지속적 유지보수와 개선 곤란
### 해결책
1. **컴포넌트 기반 구조 도입**
   - React/Vue.js 등 프레임워크 활용
   - 기능별 독립 컴포넌트화로 재사용성 및 유지보수성 향상


## 3. 그 외
1. **파이썬 타입 힌트 사용**
   - 현재 타입 힌트를 사용하지 못해 IDE의 도움을 100% 받을 수 없음
2. **Pycharm Problems 사용**
   - 파이썬은 컴파일이 없어 IDE에서 주는 warning 또는 erorr를 적극 제거해야함.
