require 'bundler/setup'

require 'fileutils'
require 'json'
require 'open3'
require 'sqlite3'
require 'yaml'

config = YAML.load_file('./config.yml')

# Get json which is infomation of vulnerability database (nvd)
FileUtils.mkdir_p("./#{config['src_path']}/nvd") unless Dir.exist?("./#{config['src_path']}/nvd")
Dir.chdir("./#{config['src_path']}/nvd") do 
  for year in config['nvd']['year']['oldest'].to_i..config['nvd']['year']['current'].to_i do
    Open3.capture3("wget #{config['nvd']['url']}/nvdcve-1.0-#{year}.json.zip")
    Open3.capture3("unzip nvdcve-1.0-#{year}.json.zip")
    Open3.capture3("rm -rf nvdcve-1.0-#{year}.json.zip") if File.exist?("nvdcve-1.0-#{year}.json.zip")
  end
end

FileUtils.mkdir_p("./#{config['db_path']}") unless Dir.exist?("./#{config['db_path']}")
# database which is infomation of CVE
db = SQLite3::Database.new("./#{config['db_path']}/cve.sqlite3")
sql = <<-SQL
CREATE TABLE cve (
id INTEGER PRIMARY KEY AUTOINCREMENT,
cve VARCHAR(200) NOT NULL,
nvd_id INTEGER NOT NULL,
description VARCHAR
)
SQL
db.execute(sql)

sql = <<-SQL
INSERT INTO cve (cve, nvd_id, description) values (?, ?, ?)
SQL
for year in config['nvd']['year']['oldest'].to_i..config['nvd']['year']['current'].to_i do
  File.open("./#{config['src_path']}/nvd/nvdcve-1.0-#{year}.json") do |file|
    cve_hash = JSON.load(file)
    db.transaction do
      cve_hash['CVE_Items'].each_with_index do |cve_item, nvd_id|
        # get CVE
        cve = cve_item['cve']['CVE_data_meta']['ID']
        # description of vulnerability
        cve_item['cve']['description']['description_data'].each do |description|
          db.execute(sql, cve, nvd_id, description['value'])
        end
      end
    end
  end
end
db.close

# CWE database
db = SQLite3::Database.new("./#{config['db_path']}/cwe.sqlite3")
sql = <<-SQL
CREATE TABLE cwe (
id INTEGER PRIMARY KEY AUTOINCREMENT,
cve VARCHAR(200) NOT NULL,
cwe INTEGER NOT NULL
)
SQL
db.execute(sql)

sql = <<-SQL
INSERT INTO cwe (cve, cwe) values (?, ?)
SQL
for year in config['nvd']['year']['oldest'].to_i..config['nvd']['year']['current'].to_i do
  File.open("./#{config['src_path']}/nvd/nvdcve-1.0-#{year}.json") do |file|
    cve_hash = JSON.load(file)
    db.transaction do
      cve_hash['CVE_Items'].each do |cve_item|
        cve = cve_item['cve']['CVE_data_meta']['ID']
        cve_item['cve']['problemtype']['problemtype_data'].each do |problemtype_data|
          problemtype_data['description'].each do |cwe_description|
            db.execute(sql, cve, cwe_description['value'])
          end
        end
      end
    end
  end
end
db.close

# cpe database
db = SQLite3::Database.new("./#{config['db_path']}/cpe.sqlite3")
sql = <<-SQL
CREATE TABLE cpe (
id INTEGER PRIMARY KEY AUTOINCREMENT,
cve VARCHAR(200) NOT NULL,
cpe VARCHAR NOT NULL
)
SQL
db.execute(sql)

sql = <<-SQL
INSERT INTO cpe (cve, cpe) values (?, ?)
SQL
for year in config['nvd']['year']['oldest'].to_i..config['nvd']['year']['current'].to_i do
  File.open("./#{config['src_path']}/nvd/nvdcve-1.0-#{year}.json") do |file|
    cve_hash = JSON.load(file)
    db.transaction do
      cve_hash['CVE_Items'].each do |cve_item|
        cve = cve_item['cve']['CVE_data_meta']['ID']
        cve_item['configurations']['nodes'].each do |node|
          if node.key?('cpe_match')
            node['cpe_match'].each do |cpe|
              db.execute(sql, cve, cpe['cpe23Uri'])
            end
          end
        end
      end
    end
  end
end

db.close


# CVSS v2
db = SQLite3::Database.new("./#{config['db_path']}/cvss_v2.sqlite3")
sql = <<-SQL
CREATE TABLE cvss_v2 (
id INTEGER PRIMARY KEY AUTOINCREMENT,
cve VARCHAR(200) NOT NULL,
vector_string VARCHAR,
access_vector VARCHAR,
access_complexity VARCHAR,
authentication VARCHAR,
confidentiality_impact VARCHAR,
cofidentiality_impact VARCHAR,
integrity_impact VARCHAR,
availability_impact VARCHAR,
base_score INTEGER
)
SQL
db.execute(sql)

sql = <<-SQL
INSERT INTO cvss_v2 (cve, vector_string, access_vector, access_complexity, authentication, confidentiality_impact, integrity_impact, availability_impact, base_score) 
values (?, ?, ?, ?, ?, ?, ?, ?, ?)
SQL
for year in config['nvd']['year']['oldest'].to_i..config['nvd']['year']['current'].to_i do
  File.open("./#{config['src_path']}/nvd/nvdcve-1.0-#{year}.json") do |file|
    cve_hash = JSON.load(file)
    db.transaction do
      cve_hash['CVE_Items'].each do |cve_item|
        cve = cve_item['cve']['CVE_data_meta']['ID']
        if cve_item['impact'].key?('baseMetricV2')
          cvss = cve_item['impact']['baseMetricV2']['cvssV2']
          db.execute(sql, cve, cvss['vectorString'], cvss['accessVector'], cvss['accessComplexity'], cvss['authentication'], cvss['confidentialityImpact'],
                     cvss['integrityImpact'], cvss['availabilityImpact'], cvss['baseScore'])
        end
      end
    end
  end
end
db.close

# CVSS v3
db = SQLite3::Database.new("./#{config['db_path']}/cvss_v3.sqlite3")
sql = <<-SQL
CREATE TABLE cvss_v3 (
id INTEGER PRIMARY KEY AUTOINCREMENT,
cve VARCHAR(200) NOT NULL,
vector_string VARCHAR,
attack_vector VARCHAR,
attack_complexity VARCHAR,
privileges_required VARCHAR,
user_interaction VARCHAR,
scope VARCHAR,
confidentiality_impact VARCHAR,
integrity_impact VARCHAR,
availability_impact VARCHAR,
base_score INTEGER,
base_severity VARCHAR
)
SQL
db.execute(sql)

sql = <<-SQL
INSERT INTO cvss_v3 (cve, vector_string, attack_vector, attack_complexity, privileges_required, user_interaction,
scope, confidentiality_impact, integrity_impact, availability_impact, base_score, base_severity) 
values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
SQL
for year in config['nvd']['year']['oldest'].to_i..config['nvd']['year']['current'].to_i do
  File.open("./#{config['src_path']}/nvd/nvdcve-1.0-#{year}.json") do |file|
    cve_hash = JSON.load(file)
    db.transaction do
      cve_hash['CVE_Items'].each do |cve_item|
        cve = cve_item['cve']['CVE_data_meta']['ID']
        if cve_item['impact'].key?('baseMetricV3')
          cvss = cve_item['impact']['baseMetricV3']['cvssV3']
          db.execute(sql, cve, cvss['vectorString'], cvss['attackVector'], cvss['attackComplexity'], cvss['privilegesRequired'],
                     cvss['userInteraction'], cvss['scope'], cvss['confidentialityImpact'], cvss['integrityImpact'],
                     cvss['availabilityImpact'], cvss['baseScore'], cvss['baseSeverity'])
        end
      end
    end
  end
end
db.close

db = SQLite3::Database.new("./#{config['db_path']}/vultest.sqlite3")

sql = <<SQL
CREATE TABLE configs (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  cve VARCHAR(200) NOT NULL,
  name VARCHAR(200) NOT NULL,
  config_path VARCHAR(200) NOT NULL,
  module_path VARCHAR(200) NOT NULL
);
SQL
db.execute(sql)

sql = 'INSERT INTO configs (cve, name, config_path, module_path) values (? ,?, ?, ?)'
data = YAML.load_file("./#{config['src_path']}/vultest/vultest_data.yml")
data.each do |vuldata|
  db.execute(sql, vuldata['vuln']['cve'], vuldata['vuln']['name'], vuldata['vuln']['data']['env_path'], vuldata['vuln']['data']['attack_path'])
end
db.close
