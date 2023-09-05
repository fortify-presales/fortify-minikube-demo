minikube kubectl -- run mysql-client --rm --tty -i --restart='Never' `
    --image  docker.io/bitnami/mysql:8.0.30-debian-11-r6 `
    --namespace default `
    --command -- mysql -h mysql.default.svc.cluster.local -uroot -ppassword `
    -e "use ssc_db; update fortifyuser set requirePasswordChange='N', dateFrozen=NULL, failedLoginAttempts=0 where id=1;"
# below command only working if logged into mysql in console?
#minikube kubectl -- run mysql-client --rm --tty -i --restart='Never' `
#    --image  docker.io/bitnami/mysql:8.0.30-debian-11-r6 `
#    --namespace default `
#    --command -- mysql -h mysql.default.svc.cluster.local -uroot -ppassword `
#    -e "use ssc_db; update fortifyuser set requirePasswordChange='N', dateFrozen=NULL, failedLoginAttempts=0, password='{bcrypt}$2a$10$3QTljAADHzeu4Fn5tGjXd.JPuIpYdxbf6150i9/WJFsS2NpVpTVV.' where id=1;"
